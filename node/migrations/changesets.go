package migrations

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math/big"
	"time"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/extensions/hooks"
	"github.com/trufnetwork/kwil-db/extensions/resolutions"
	"github.com/trufnetwork/kwil-db/node/pg"
	"github.com/trufnetwork/kwil-db/node/types/sql"
	"github.com/trufnetwork/kwil-db/node/voting"
)

const (
	changesetsEndBlockHook    = "changesets"
	changesetMigrationVersion = 0
)

var (
	ErrNoMoreChunksToRead = errors.New("no more chunks to read")
	ErrChangesetNotFound  = errors.New("changeset not found")

	migrationCompleted = "Migration completed. The migration section in genesis.json and the migrate_from configuration in config.toml are no longer relevant and should be removed."
)

func init() {
	err := resolutions.RegisterResolution(voting.ChangesetMigrationEventType, resolutions.ModAdd, changesetMigrationResolution)
	if err != nil {
		panic(err)
	}

	err = hooks.RegisterEndBlockHook(changesetsEndBlockHook, applyChangesets)
	if err != nil {
		panic(err)
	}
}

// During network migration, the new node starts with the genesis state equal to the state of the old chain at the migration start height.
// The changeset migration system is used to replicate changesets from the old chain to the new chain in order to
// sync the state changes that occur on the old chain after the migration start height.
// These changesets are applied in the order of the block heights starting from the migration start height.
// Since the changesets can be very large and these changesets are to be sent through the voting system in the resolution body,
// and are constrained by the block sizes, the changesets are split into chunks and sent through the voting system.
// ChangesetMigration is the struct that represents the changeset migration chunk.
type changesetMigration struct {
	// Height is the block height the changeset belongs to.
	Height uint64

	// ChangesetIdx is the index of the changeset chunk in the block.
	// Indexes starts from 0.
	ChunkIdx uint64

	// TotalChunks is the total number of chunks in the changeset.
	TotalChunks uint64

	// Changeset is the serialized changeset chunk.
	Changeset []byte

	// PreviousBlock is the last block with non empty changesets.
	PreviousBlock uint64
}

// MarshalBinary marshals the ChangesetMigration into a binary format.
func (cs *changesetMigration) MarshalBinary() ([]byte, error) {
	buf := &bytes.Buffer{}

	// version
	if err := binary.Write(buf, types.SerializationByteOrder, int16(changesetMigrationVersion)); err != nil {
		return nil, err
	}

	// height
	if err := binary.Write(buf, types.SerializationByteOrder, cs.Height); err != nil {
		return nil, err
	}

	// chunk index
	if err := binary.Write(buf, types.SerializationByteOrder, cs.ChunkIdx); err != nil {
		return nil, err
	}

	// total chunks
	if err := binary.Write(buf, types.SerializationByteOrder, cs.TotalChunks); err != nil {
		return nil, err
	}

	// changeset bytes
	if err := types.WriteBytes(buf, cs.Changeset); err != nil {
		return nil, err
	}

	// previous block
	if err := binary.Write(buf, types.SerializationByteOrder, cs.PreviousBlock); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// UnmarshalBinary unmarshals the ChangesetMigration from a binary format.
func (cs *changesetMigration) UnmarshalBinary(data []byte) error {
	buf := bytes.NewReader(data)

	// version
	var version int16
	if err := binary.Read(buf, types.SerializationByteOrder, &version); err != nil {
		return err
	}
	if version != changesetMigrationVersion {
		return errors.New("invalid changeset migration version")
	}

	// height
	if err := binary.Read(buf, types.SerializationByteOrder, &cs.Height); err != nil {
		return err
	}

	// chunk index
	if err := binary.Read(buf, types.SerializationByteOrder, &cs.ChunkIdx); err != nil {
		return err
	}

	// total chunks
	if err := binary.Read(buf, types.SerializationByteOrder, &cs.TotalChunks); err != nil {
		return err
	}

	// changeset bytes
	changeset, err := types.ReadBytes(buf)
	if err != nil {
		return err
	}
	cs.Changeset = changeset

	// previous block
	if err := binary.Read(buf, types.SerializationByteOrder, &cs.PreviousBlock); err != nil {
		return err
	}

	return nil
}

// ChangesetMigrationResolution is the definition for changeset migration vote type in Kwil's voting system.
// ChangesetMigrationResolution is responsible for applying changesets from the old chain to the new chain.
// Once the changeset chunk is approved through the voting system, the chunk is added to the database.
// Once all the chunks for a particular height are received, the changeset is applied and the chunks are deleted.
// The changesets are applied in the order of block heights.
var changesetMigrationResolution = resolutions.ResolutionConfig{
	ConfirmationThreshold: big.NewRat(2, 3),
	ExpirationPeriod:      24 * time.Hour, // 1 day
	ResolveFunc: func(ctx context.Context, app *common.App, resolution *resolutions.Resolution, block *common.BlockContext) error {
		var migration changesetMigration
		err := migration.UnmarshalBinary(resolution.Body)
		if err != nil {
			return err
		}

		// insert the changeset into the database
		app.Service.Logger.Debug("insert changeset chunk", "height", migration.Height, "chunk_idx", migration.ChunkIdx)
		tx, err := app.DB.BeginTx(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)

		// insert the changeset into the database
		err = migration.insertChangeset(ctx, tx)
		if err != nil {
			return err
		}

		// Commit the changeset chunk to the database
		return tx.Commit(ctx)
	},
}

// applyChangesets is an EndBlockHook that applies the changesets to the database in the order
// of block heights starting from the migration start height to the migration end height.
func applyChangesets(ctx context.Context, app *common.App, blockCtx *common.BlockContext) error {
	if blockCtx.ChainContext.MigrationParams == nil {
		return nil
	}
	startHeight := blockCtx.ChainContext.MigrationParams.StartHeight
	endHeight := blockCtx.ChainContext.MigrationParams.EndHeight

	tx, err := app.DB.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// get the last changeset height applied
	lastChangeset, err := getLastChangeset(ctx, tx)
	if err != nil {
		return err
	}

	if lastChangeset == endHeight {
		// migration completed
		blockCtx.ChainContext.MigrationParams = nil
		app.Service.Logger.Info(migrationCompleted, "height", lastChangeset)
		blockCtx.ChainContext.NetworkParameters.MigrationStatus = types.NoActiveMigration
		return nil
	}

	if lastChangeset == -1 {
		lastChangeset = 0 // set the last changeset to 0, because migration declaration doesn't accept int64 (-1)
	}

	for {
		// get the metadata for the earliest height that has not been applied
		height, prevHeight, totalChunks, chunksReceived, err := getEarliestChangesetMetadata(ctx, tx)
		if err != nil {
			return err
		}

		if height == -1 { // no changesets to apply
			break
		}

		if height != startHeight && prevHeight != lastChangeset {
			// If the previous changeset is not applied, break
			break
		}

		// If no chunks have been received or all chunks have not been received, break
		if totalChunks == -1 || totalChunks != chunksReceived {
			break
		}

		// Apply the changeset if all chunks have been received
		if err = applyChangeset(ctx, app, tx, height, totalChunks); err != nil {
			return err
		}

		app.Service.Logger.Info("Applied changesets", "height", height)

		// Delete the changeset after it has been applied
		if err = deleteChangesets(ctx, tx, height); err != nil {
			return err
		}

		// Increment the last changeset
		if err = setLastChangeset(ctx, tx, height); err != nil {
			return err
		}
		lastChangeset = height

		if height == endHeight {
			// migration completed
			blockCtx.ChainContext.MigrationParams = nil
			blockCtx.ChainContext.NetworkParameters.MigrationStatus = types.NoActiveMigration
			app.Service.Logger.Info(migrationCompleted, "height", height)
			break
		}
	}

	return tx.Commit(ctx)
}

func applyChangeset(ctx context.Context, app *common.App, db sql.TxMaker, height int64, totalChunks int64) error {
	tx, err := db.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	csReader := newChangesetReader(height, totalChunks)

	var relations []*pg.Relation
	for {
		prefix, err := csReader.Read(ctx, tx, 5)
		if err != nil {
			// no more chunks or changesets not found
			if errors.Is(err, ErrNoMoreChunksToRead) || errors.Is(err, ErrChangesetNotFound) {
				break
			}
			return err
		}

		csType, csSize := pg.DecodeStreamPrefix([5]byte(prefix))

		data, err := csReader.Read(ctx, tx, int(csSize))
		if err != nil {
			// invalid changeset
			return err
		}
		// Read the changeset type
		switch csType {
		case pg.RelationType:
			rel := &pg.Relation{}
			if err = rel.UnmarshalBinary(data); err != nil {
				return err
			}
			relations = append(relations, rel)

		case pg.ChangesetEntryType:
			ce := &pg.ChangesetEntry{}
			if err = ce.UnmarshalBinary(data); err != nil {
				return err
			}

			// apply the changeset entry
			if err = ce.ApplyChangesetEntry(ctx, tx, relations[ce.RelationIdx]); err != nil {
				return err
			}

		case pg.BlockSpendsType:
			bs := &BlockSpends{}
			if err = bs.UnmarshalBinary(data); err != nil {
				return err
			}

			// apply the block spends
			for _, spend := range bs.Spends {
				if err = app.Accounts.ApplySpend(ctx, tx, spend.Account, spend.Amount, int64(spend.Nonce)); err != nil {
					return err
				}
			}

		default:
			return errors.New("unknown changeset type")
		}
	}
	return tx.Commit(ctx)
}

type changesetReader struct {
	height      int64
	chunkIdx    int64
	totalChunks int64
	data        []byte
}

func newChangesetReader(height int64, totalChunks int64) *changesetReader {
	return &changesetReader{
		height:      height,
		totalChunks: totalChunks,
	}
}

func (r *changesetReader) Read(ctx context.Context, tx sql.Executor, numBytesToRead int) ([]byte, error) {
	for len(r.data) < numBytesToRead {
		if r.chunkIdx >= r.totalChunks {
			return nil, ErrNoMoreChunksToRead
		}

		bts, err := getChangeset(ctx, tx, r.height, r.chunkIdx)
		if err != nil {
			return nil, err
		}

		r.data = append(r.data, bts...)
		r.chunkIdx += 1
	}

	data := r.data[:numBytesToRead]
	r.data = r.data[numBytesToRead:]

	return data, nil
}

// insertChangesetMigration inserts the changeset migration into the database.
// This inserts the changeset metadata for a particular height if it does not exist.
// It also inserts the changeset chunk into the database.
func (cm *changesetMigration) insertChangeset(ctx context.Context, db sql.TxMaker) error {
	tx, err := db.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	//  Check if the changeset metadata entry exists, if not, create it
	if err := insertChangesetMetadata(ctx, tx, int64(cm.Height), int64(cm.TotalChunks), int64(cm.PreviousBlock)); err != nil {
		return err
	}

	// check if this is not previously received
	var exists bool
	if exists, err = changesetChunkExists(ctx, tx, int64(cm.Height), int64(cm.ChunkIdx)); err != nil {
		return err
	}

	if exists { // already received, ignore the changeset chunk
		return nil
	}

	// insert the changeset
	if err = insertChangesetChunk(ctx, tx, int64(cm.Height), int64(cm.ChunkIdx), cm.Changeset); err != nil {
		return err
	}

	// mark the chunk as received
	if _, err = tx.Execute(ctx, updateChangesetMetadataSQL, int64(cm.Height)); err != nil {
		return err
	}

	return tx.Commit(ctx)
}
