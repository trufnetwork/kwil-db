package migrations

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/jpillora/backoff"
	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/client"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/extensions/listeners"
	"github.com/trufnetwork/kwil-db/node/voting"
)

// Changeset Extension polls the changesets from the old chain  during migration.
// The changesets received are broadcasted to the eventstore under ChangesetMigrationEvent type for voting.
// The changesets are then applied to the new chain's database once the resolution is approved.
const (
	ListenerName = "migrations"
	retryDelay   = 1 * time.Second // polling frequency for changesets
	maxRetries   = 10              // max retries for polling changesets
)

func init() {
	// Register the listener with the name "migrations"
	err := listeners.RegisterListener(ListenerName, Start)
	if err != nil {
		panic(err)
	}
}

type MigrationConfig struct {
	// StartHeight is the block height at which the migration started on the old chain.
	StartHeight uint64

	// End height is the block height at which the migration ended on the old chain.
	EndHeight uint64

	// ListenAddress is the address of the kwild server to receive changesets from.
	ListenAddress string
}

type migrationListener struct {
	// Config is the migration configuration
	config *MigrationConfig

	// Client is the kwild RPC client to the old chain
	client *client.Client

	// currentHeight is the current block height to be processed
	currentHeight uint64

	// eventStore is the event store to broadcast the changeset migration events
	eventStore listeners.EventStore

	changesetSize int64

	// logger
	logger log.Logger
}

func Start(ctx context.Context, service *common.Service, eventStore listeners.EventStore) error {
	// Get the migration config from the service
	cfg := &MigrationConfig{}

	if !service.LocalConfig.Migrations.Enable {
		service.Logger.Warn("no migration config provided, skipping migration listener")
		return nil // no migration config provided
	}

	if service.LocalConfig.Migrations.MigrateFrom == "" {
		return errors.New("migrate_from is mandatory for migration")
	}

	cfg.ListenAddress = service.LocalConfig.Migrations.MigrateFrom
	cfg.StartHeight = uint64(service.GenesisConfig.Migration.StartHeight)
	cfg.EndHeight = uint64(service.GenesisConfig.Migration.EndHeight)

	// Kwild RPC client connection to the old chain
	clt, err := client.NewClient(ctx, cfg.ListenAddress, nil)
	if err != nil {
		return err
	}

	// Get the block height of the last changesets received from the old chain
	// If no height is found, start from the start height of the migrations.
	// If all the changesets have already been received, the listener will exit.
	var currentHeight, lastHeight uint64
	lastHeight, err = getLastStoredHeight(ctx, eventStore)
	if err != nil {
		return err
	}

	if lastHeight == 0 {
		currentHeight = cfg.StartHeight
	} else if lastHeight >= cfg.EndHeight {
		service.Logger.Info("all the changesets have been synced, closing the migrations listener.", "height", lastHeight)
		return nil
	} else {
		currentHeight = lastHeight + 1
	}

	blockSize := service.GenesisConfig.MaxBlockSize

	// Create the migration listener
	listener := &migrationListener{
		config:        cfg,
		client:        clt,
		currentHeight: currentHeight,
		eventStore:    eventStore,
		logger:        service.Logger,
		changesetSize: blockSize / 3, // 1/3 of the block size
	}

	// Start polling the admin server for changesets
	service.Logger.Info("start syncing changesets from old chain", "startHeight", cfg.StartHeight)
	return listener.retrieveChangesets(ctx)
}

func (ml *migrationListener) retrieveChangesets(ctx context.Context) error {
	for {
		if ml.currentHeight > ml.config.EndHeight {
			// Synced up with the old chain, no more changesets to pull. Close the listener
			ml.logger.Info("changesets have been synchronized with the old chain", "height", ml.currentHeight)
			return nil
		}

		// Get the changeset metadata from the admin server
		// retries till the metadata is received successfully using exponential backoff
		// backoff timer is reset on each successful metadata retrieval or after max retries
		numChunks, chunkSizes, err := ml.GetChangesetMetadata(ctx)
		if err != nil {
			continue // Should we return err here?
		}
		btsReceived := int64(0)

		ml.logger.Info("received changeset metadata", "height", ml.currentHeight, "numChunks", numChunks, "chunkSizes", chunkSizes)

		wg := sync.WaitGroup{}
		errChan := make(chan error, numChunks)
		for i := range numChunks {
			wg.Add(1)
			go func(chunkIdx int64) {
				defer wg.Done()
				// Check if the chunk is already received
				cs, err := getChangesetChunk(ctx, ml.eventStore, ml.currentHeight, uint64(chunkIdx))
				if err != nil {
					errChan <- err
					return
				}

				if len(cs) > 0 {
					ml.logger.Debug("changeset chunk already received", "height", ml.currentHeight, "chunk", chunkIdx)
					// Chunk already received, skip
					if int64(len(cs)) != chunkSizes[chunkIdx] {
						errChan <- fmt.Errorf("changeset size mismatch: expected %d, got %d", chunkSizes[chunkIdx], len(cs))
						return
					}

					btsReceived += int64(len(cs))
					wg.Done()
					return
				}

				// else request the changeset chunk from the old chain
				cs, err = ml.LoadChangeset(ctx, chunkIdx, chunkSizes[chunkIdx])
				if err != nil {
					errChan <- err
					return
				}

				if int64(len(cs)) != chunkSizes[chunkIdx] {
					errChan <- fmt.Errorf("changeset size mismatch for height: %d: expected %d, got %d", ml.currentHeight, chunkSizes[chunkIdx], len(cs))
					return
				}

				// Store the changeset chunk in the event store
				if err = setChangesetChunk(ctx, ml.eventStore, ml.currentHeight, uint64(chunkIdx), cs); err != nil {
					errChan <- err
					return
				}

				btsReceived += int64(len(cs))
			}(i)
		}

		// Wait for all chunks to be successfully received
		wg.Wait()
		close(errChan)

		// check errChan for all the errors
		var errs error
		for err := range errChan {
			errs = errors.Join(errs, err)
		}

		if errs != nil {
			return errs
		}

		// Add the changeset migration event to the event store for voting
		if err = ml.addChangesetEvent(ctx, ml.currentHeight, numChunks, btsReceived); err != nil {
			return err
		}

		if err = setLastStoredHeight(ctx, ml.eventStore, ml.currentHeight); err != nil {
			return err
		}
		ml.currentHeight++

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(retryDelay):
		}
	}
}

const (
	emptyChangesetChunksCount = 1
	emptyChangesetChunkIdx    = 0
)

// AddEvent adds the chaneset migration event to the event store for voting
// only if the changeset is not empty. If the changeset is empty, it is skipped.
// This method readjusts the changeset sizes depending on the current chains block size.
func (ml *migrationListener) addChangesetEvent(ctx context.Context, height uint64, numChunks int64, changesetSize int64) error {
	// Check if the changeset is empty and skip it if it is not at the end height
	// Add the changeset for the end height even if it is empty to signal the end of the migration
	if height != ml.config.EndHeight && numChunks == 0 {
		ml.logger.Debug("empty changesets for height", "height", height)
		return nil
	}

	prevHeight, err := getLastChangesetBlockHeight(ctx, ml.eventStore)
	if err != nil {
		return err
	}

	// numChunks is the total number of chunks for the changeset for the given height
	// received from the old chain. totalChunks is the total number of chunks
	// the changeset will be split into based on the current chain's block size.
	totalChunks := changesetSize / ml.changesetSize
	if changesetSize%ml.changesetSize != 0 {
		totalChunks++
	}

	// reader to read the changeset chunks according to adjusted chunk size
	reader := newChunkReader(height, totalChunks)

	if numChunks == 0 && height == ml.config.EndHeight {
		// Add the changeset migration event for the end height even if it is empty
		if err := ml.addEvent(height, prevHeight, emptyChangesetChunksCount, emptyChangesetChunkIdx, nil); err != nil {
			return err
		}
	} else {
		for i := range totalChunks {
			// Read as many bytes as the changeset size
			cs, err := reader.Read(ctx, ml.eventStore, int(ml.changesetSize))
			if err != nil {
				return err
			}

			if err = ml.addEvent(height, prevHeight, uint64(totalChunks), uint64(i), cs); err != nil {
				return err
			}
		}
	}

	// Set the last changeset block height
	if err = setLastChangesetBlockHeight(ctx, ml.eventStore, height); err != nil {
		return err
	}

	// delete the changeset chunks from the event store
	for i := range totalChunks {
		if err = deleteChangesetChunk(ctx, ml.eventStore, height, uint64(i)); err != nil {
			return err
		}
	}

	return nil
}

func (ml *migrationListener) addEvent(height, prevHeight, totalChunks, chunkIdx uint64, csData []byte) error {
	evt := &changesetMigration{
		Height:        height,
		TotalChunks:   totalChunks,
		ChunkIdx:      chunkIdx,
		Changeset:     csData,
		PreviousBlock: prevHeight,
	}

	csEvt, err := evt.MarshalBinary()
	if err != nil {
		ml.logger.Error("failed to marshal changeset migration event", "error", err)
		return err
	}

	ml.logger.Info("adding changeset migration event", "height", height, "size", csData, "prevHeight", int(prevHeight))

	// Broadcast the changeset migration event to the event store for voting
	err = ml.eventStore.Broadcast(context.Background(), voting.ChangesetMigrationEventType, csEvt)
	if err != nil {
		return fmt.Errorf("failed to broadcast changeset migration event: %w", err)
	}

	return nil
}

type chunkReader struct {
	height      uint64
	chunkIdx    uint64
	totalChunks int64
	data        []byte
}

func newChunkReader(height uint64, totalChunks int64) *chunkReader {
	return &chunkReader{
		height:      height,
		totalChunks: totalChunks,
	}
}

// Read function returns next numBytesToRead bytes from the changeset chunks
func (r *chunkReader) Read(ctx context.Context, eventStore listeners.EventStore, numBytesToRead int) ([]byte, error) {
	for len(r.data) < numBytesToRead {
		if r.chunkIdx >= uint64(r.totalChunks) {
			return r.data, nil // no more chunks to read
		}

		bts, err := getChangesetChunk(ctx, eventStore, r.height, r.chunkIdx)
		if err != nil {
			return nil, err
		}

		r.data = append(r.data, bts...)
		r.chunkIdx++
	}

	data := r.data[:numBytesToRead]
	r.data = r.data[numBytesToRead:]

	return data, nil
}

func (ml *migrationListener) GetChangesetMetadata(ctx context.Context) (totalChunks int64, chunkSizes []int64, err error) {
	err = retry(ctx, maxRetries, func() error {
		totalChunks, chunkSizes, err = ml.client.ChangesetMetadata(ctx, int64(ml.currentHeight))
		return err
	})
	return totalChunks, chunkSizes, err
}

func (ml *migrationListener) LoadChangeset(ctx context.Context, chunkIdx int64, chunkSize int64) (cs []byte, err error) {
	err = retry(ctx, maxRetries, func() error {
		if cs, err = ml.client.LoadChangeset(ctx, int64(ml.currentHeight), chunkIdx); err != nil {
			return err
		}

		if int64(len(cs)) != chunkSize {
			return fmt.Errorf("changeset size mismatch: expected %d, got %d. Maybe try other rpc provider", chunkSize, len(cs))
		}

		return nil
	})
	return cs, err
}

func (c *MigrationConfig) Map() map[string]string {
	return map[string]string{
		"start_height":   strconv.FormatUint(c.StartHeight, 10),
		"end_height":     strconv.FormatUint(c.EndHeight, 10),
		"listen_address": c.ListenAddress,
	}
}

var (
	// lastHeightKey is the key used to store the last height processed by the listener
	lastHeightKey    = []byte("lh")
	lastChangesetKey = []byte("lc")
	chunkKey         = []byte("ck")
)

// getLastStoredHeight gets the last height stored by the KV store
func getLastStoredHeight(ctx context.Context, eventStore listeners.EventStore) (uint64, error) {
	// get the last confirmed block height processed by the listener
	lastHeight, err := eventStore.Get(ctx, lastHeightKey)
	if err != nil {
		return 0, fmt.Errorf("failed to get last block height: %w", err)
	}

	if len(lastHeight) == 0 {
		return 0, nil
	}

	return binary.LittleEndian.Uint64(lastHeight), nil
}

// setLastStoredHeight sets the last height stored by the KV store
func setLastStoredHeight(ctx context.Context, eventStore listeners.EventStore, height uint64) error {
	heightBts := make([]byte, 8)
	binary.LittleEndian.PutUint64(heightBts, height)

	// set the last confirmed block height processed by the listener
	err := eventStore.Set(ctx, lastHeightKey, heightBts)
	if err != nil {
		return fmt.Errorf("failed to set last block height: %w", err)
	}
	return nil
}

// getLastStoredHeight gets the last height stored by the KV store
func getLastChangesetBlockHeight(ctx context.Context, eventStore listeners.EventStore) (uint64, error) {
	// get the last confirmed block height processed by the listener
	lastHeight, err := eventStore.Get(ctx, lastChangesetKey)
	if err != nil {
		return 0, fmt.Errorf("failed to get last block height: %w", err)
	}

	if len(lastHeight) == 0 {
		return 0, nil
	}

	return binary.LittleEndian.Uint64(lastHeight), nil
}

// setLastStoredHeight sets the last height stored by the KV store
func setLastChangesetBlockHeight(ctx context.Context, eventStore listeners.EventStore, height uint64) error {
	heightBts := make([]byte, 8)
	binary.LittleEndian.PutUint64(heightBts, height)

	// set the last confirmed block height processed by the listener
	err := eventStore.Set(ctx, lastChangesetKey, heightBts)
	if err != nil {
		return fmt.Errorf("failed to set last block height: %w", err)
	}
	return nil
}

// SetChunk sets the changeset chunk of the given height and chunk index
func setChangesetChunk(ctx context.Context, eventStore listeners.EventStore, height, chunkIdx uint64, chunk []byte) error {
	suffix := []byte(fmt.Sprintf("%d-%d", height, chunkIdx))
	key := append(chunkKey, suffix...)
	return eventStore.Set(ctx, key, chunk)
}

// GetChunk gets the changeset chunk of the given height and chunk index
func getChangesetChunk(ctx context.Context, eventStore listeners.EventStore, height, chunkIdx uint64) ([]byte, error) {
	suffix := []byte(fmt.Sprintf("%d-%d", height, chunkIdx))
	key := append(chunkKey, suffix...)
	return eventStore.Get(ctx, key)
}

func deleteChangesetChunk(ctx context.Context, eventStore listeners.EventStore, height, chunkIdx uint64) error {
	suffix := []byte(fmt.Sprintf("%d-%d", height, chunkIdx))
	key := append(chunkKey, suffix...)
	return eventStore.Delete(ctx, key)
}

// retry will retry the function until it is successful, or reached the max retries
func retry(ctx context.Context, maxRetries int64, fn func() error) error {
	retrier := &backoff.Backoff{
		Min:    1 * time.Second,
		Max:    10 * time.Second,
		Factor: 2,
		Jitter: true,
	}

	for {
		err := fn()
		if err == nil {
			return nil
		}

		// fail after maxRetries retries
		if retrier.Attempt() > float64(maxRetries) {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(retrier.Duration()):
		}
	}
}
