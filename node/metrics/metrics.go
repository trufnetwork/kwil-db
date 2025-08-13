package metrics

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// These are the global instances of the metrics grouped by the meter name.
// Until and unless Start is called, these are no-op meters.
var (
	RPC       RPCMetrics       = rpcMetrics{}
	DB        DBMetrics        = dbMetrics{}
	Consensus ConsensusMetrics = consensusMetrics{}
	Node      NodeMetrics      = nodeMetrics{}
	Store     StoreMetrics     = storeMetrics{}
)

// If we do not want to use the otel global meter provider, we can create our
// own package-level meter provider.  Initially can use the noop meter, and on
// Start we can switch to the real meter provider. This would permit us to keep
// the telemetry from third party packages that use the global otel meter out of
// our metrics that we export.  On the other hand, we may actually want those
// third party metrics.
//
// Another complication of using our own package level meter provider is that we
// must create the meters *after* instantiating with real meter provider rather
// than the initial no-op provider. We don't have this constraint with the otel
// global provider because when a real provider is actually set, all the meters
// are recreated to the newly delegated provider within the global.
//
// var (
// 	meterProvider metric.MeterProvider = metricnoop.NewMeterProvider()
// 	traceProvider trace.TracerProvider = tracenoop.NewTracerProvider()
// )

var (
	// RPC metrics
	requests    metric.Int64Counter
	latencyHist metric.Float64Histogram

	// DB metrics
	dbConnsActive      metric.Int64UpDownCounter
	dbQueryLatencyHist metric.Float64Histogram
	dbQueryErrorCount  metric.Int64Counter

	// Engine metrics
	// engineNumNamespaces metric.Int64Gauge // TODO
	// engineStatementParseCount metric.Int64Counter

	// Accounts metrics
	// accountsNum metric.Int64ObservableGauge // callback should get account count?
	// cacheMissesCounter metric.Int64Counter
	// cacheHitsCounter  metric.Int64Counter

	// Consensus metrics
	commitLatencyHist metric.Float64Histogram // from start of executeblock to commit
	commitCounter     metric.Int64Counter
	execLatencyHist   metric.Float64Histogram // from start of executeblock to commit
	execCounter       metric.Int64Counter

	// Node / p2p metrics
	numPeersGauge            metric.Int64Gauge
	downloadedBlocksCounter  metric.Int64Counter
	servedBlocksCounter      metric.Int64Counter
	servedBlockBytesCounter  metric.Int64Counter
	advertisementCounter     metric.Int64Counter
	advertiseRejectCounter   metric.Int64Counter
	advertiseAcceptCounter   metric.Int64Counter
	txReannounceCounter      metric.Int64Counter
	txReannounceBytesCounter metric.Int64Counter

	// Blacklist metrics
	blacklistOperationsCounter  metric.Int64Counter // blacklist add/remove operations
	blacklistedPeersGauge       metric.Int64Gauge   // current number of blacklisted peers
	autoBlacklistCounter        metric.Int64Counter // auto-blacklist events
	blacklistConnectionsBlocked metric.Int64Counter // blocked connections due to blacklist

	// Block store metrics
	bsBlocksStoredCounter          metric.Int64Counter
	bsBlockBytesStoredCounter      metric.Int64Counter
	bsBlocksRetrievedCounter       metric.Int64Counter
	bsBlockBytesRetrievedCounter   metric.Int64Counter
	bsTransactionsRetrievedCounter metric.Int64Counter
)

const (
	// DBMeterName is the name of the meter for DB metrics. Use the global DB
	// instance to access use these metrics.
	DBMeterName = "github.com/trufnetwork/kwil-db/node/pg"

	// RPCMeterName is the name of the meter for RPC metrics. Use the global RPC
	// instance to access use these metrics.
	RPCMeterName = "github.com/trufnetwork/kwil-db/node/services/jsonrpc" // currently the http server, but may be used in services like services/jsonrpc/usersvc

	NodeMeterName = "github.com/trufnetwork/kwil-db/node" // node and node/peers

	EngineMeterName = "github.com/trufnetwork/kwil-db/node/engine" // maybe split into engine/interpreter and engin/parse and engine/planner

	ConsensusMeterName = "github.com/trufnetwork/kwil-db/node/consensus"

	BlockProcessorMeterName = "github.com/trufnetwork/kwil-db/node/block_processor"

	MempoolMeterName = "github.com/trufnetwork/kwil-db/node/mempool"

	BlockStoreMeterName = "github.com/trufnetwork/kwil-db/node/store"

	AccountsMeterName = "github.com/trufnetwork/kwil-db/node/accounts"
)

// init sets up all meters and instruments. Initially, the no-op meter
// provider is used until and unless the actual OTEL providers and exporters are
// configured and started with Start.
func init() {
	// DB metrics
	dbMeter := otel.Meter(DBMeterName)
	// active connections from the DB connection pool
	dbConnsActive, _ = dbMeter.Int64UpDownCounter("connections.active")
	dbQueryLatencyHist, _ = dbMeter.Float64Histogram("query.latency")
	dbQueryErrorCount, _ = dbMeter.Int64Counter("query.errors")

	// RPC metrics
	rpcMeter := otel.Meter(RPCMeterName)
	requests, _ = rpcMeter.Int64Counter("requests.total")
	latencyHist, _ = rpcMeter.Float64Histogram("requests.duration")

	// Node metrics
	nodeMeter := otel.Meter(NodeMeterName)
	numPeersGauge, _ = nodeMeter.Int64Gauge("node.peers.total")
	downloadedBlocksCounter, _ = nodeMeter.Int64Counter("node.blocks_downloaded.count")
	servedBlocksCounter, _ = nodeMeter.Int64Counter("node.blocks_served.count")
	servedBlockBytesCounter, _ = nodeMeter.Int64Counter("node.blocks_served.bytes")
	advertisementCounter, _ = nodeMeter.Int64Counter("node.advertisements_sent.count")
	advertiseRejectCounter, _ = nodeMeter.Int64Counter("node.advertisements_sent.reject.count")
	advertiseAcceptCounter, _ = nodeMeter.Int64Counter("node.advertisements_sent.accept.count")
	txReannounceCounter, _ = nodeMeter.Int64Counter("node.tx_reannounce.count")
	txReannounceBytesCounter, _ = nodeMeter.Int64Counter("node.tx_reannounce.bytes")

	// Blacklist metrics
	blacklistOperationsCounter, _ = nodeMeter.Int64Counter("node.blacklist.operations.count")
	blacklistedPeersGauge, _ = nodeMeter.Int64Gauge("node.blacklist.peers.total")
	autoBlacklistCounter, _ = nodeMeter.Int64Counter("node.blacklist.auto.count")
	blacklistConnectionsBlocked, _ = nodeMeter.Int64Counter("node.blacklist.connections_blocked.count")
	// rebroadcasts etc...

	// Consensus metrics
	consensusMeter := otel.Meter(ConsensusMeterName)
	commitLatencyHist, _ = consensusMeter.Float64Histogram("consensus.commit.latency")
	commitCounter, _ = consensusMeter.Int64Counter("consensus.commit.total")
	execLatencyHist, _ = consensusMeter.Float64Histogram("consensus.exec.latency")
	execCounter, _ = consensusMeter.Int64Counter("consensus.exec.total")

	// Block store metrics: blocks stored, blocks retrieved, bytes stored, bytes retrieved (are these separate or just attributes and combine?)
	storeMeter := otel.Meter(BlockStoreMeterName)
	bsBlocksStoredCounter, _ = storeMeter.Int64Counter("blocks.stored.count")
	bsBlockBytesStoredCounter, _ = storeMeter.Int64Counter("blocks.stored.bytes")
	bsBlocksRetrievedCounter, _ = storeMeter.Int64Counter("blocks.retrieved.count")
	bsBlockBytesRetrievedCounter, _ = storeMeter.Int64Counter("blocks.retrieved.bytes")
	bsTransactionsRetrievedCounter, _ = storeMeter.Int64Counter("transactions.retrieved.count")
}

type storeMetrics struct{}

type StoreMetrics interface {
	BlockStored(ctx context.Context, blockHeight, size int64)
	BlockRetrieved(ctx context.Context, blockHeight, size int64)
	TransactionRetrieved(ctx context.Context)
}

func (storeMetrics) BlockStored(ctx context.Context, blockHeight, size int64) {
	bsBlocksStoredCounter.Add(ctx, 1,
		metric.WithAttributes(attribute.Int64("height", blockHeight), attribute.Int64("size", size)),
	)
	bsBlockBytesStoredCounter.Add(ctx, size,
		metric.WithAttributes(attribute.Int64("height", blockHeight)),
	)
}

func (storeMetrics) BlockRetrieved(ctx context.Context, blockHeight, size int64) {
	bsBlocksRetrievedCounter.Add(ctx, 1,
		metric.WithAttributes(attribute.Int64("height", blockHeight), attribute.Int64("size", size)),
	)
	bsBlockBytesRetrievedCounter.Add(ctx, size,
		metric.WithAttributes(attribute.Int64("height", blockHeight)),
	)
}

func (storeMetrics) TransactionRetrieved(ctx context.Context) {
	bsTransactionsRetrievedCounter.Add(ctx, 1)
}

type NodeMetrics interface {
	PeerCount(ctx context.Context, numPeers int)
	DownloadedBlock(ctx context.Context, blockHeight, size int64)
	ServedBlock(ctx context.Context, blockHeight, size int64)
	Advertised(ctx context.Context, protocol string)
	AdvertiseRejected(ctx context.Context, protocol string)
	AdvertiseServed(ctx context.Context, protocol string, contentLen int64)
	TxnsReannounced(ctx context.Context, num, totalSize int64)

	// Blacklist metrics methods
	BlacklistOperation(ctx context.Context, operation, reason string, permanent bool)
	BlacklistedPeerCount(ctx context.Context, count int)
	AutoBlacklistEvent(ctx context.Context, reason string, attempts int64)
	BlockedConnection(ctx context.Context, direction, reason string)
}

type nodeMetrics struct{}

// PeerCount logs the number of peers currently connected to the node.
func (nodeMetrics) PeerCount(ctx context.Context, numPeers int) {
	numPeersGauge.Record(ctx, int64(numPeers))
}

func (nodeMetrics) DownloadedBlock(ctx context.Context, blockHeight, size int64) {
	downloadedBlocksCounter.Add(ctx, 1,
		metric.WithAttributes(attribute.Int64("height", blockHeight), attribute.Int64("size", size)),
	)
}

func (nodeMetrics) ServedBlock(ctx context.Context, blockHeight, size int64) {
	servedBlocksCounter.Add(ctx, 1,
		metric.WithAttributes(attribute.Int64("height", blockHeight), attribute.Int64("size", size)),
	)
	servedBlockBytesCounter.Add(ctx, size,
		metric.WithAttributes(attribute.Int64("height", blockHeight)),
	)
}

func (nodeMetrics) Advertised(ctx context.Context, protocol string) {
	advertisementCounter.Add(ctx, 1,
		metric.WithAttributes(attribute.String("proto", protocol)),
	)
}

func (nodeMetrics) AdvertiseRejected(ctx context.Context, protocol string) {
	advertiseRejectCounter.Add(ctx, 1,
		metric.WithAttributes(attribute.String("proto", protocol)),
	)
}

func (nodeMetrics) AdvertiseServed(ctx context.Context, protocol string, contentLen int64) {
	advertiseAcceptCounter.Add(ctx, 1,
		metric.WithAttributes(attribute.String("proto", protocol),
			attribute.Int64("size", contentLen)),
	)
}

func (nodeMetrics) TxnsReannounced(ctx context.Context, num, totalSize int64) {
	txReannounceCounter.Add(ctx, num,
		metric.WithAttributes(attribute.Int64("size", totalSize)),
	)
	txReannounceBytesCounter.Add(ctx, totalSize)
}

// BlacklistOperation records a blacklist add or remove operation
func (nodeMetrics) BlacklistOperation(ctx context.Context, operation, reason string, permanent bool) {
	blacklistOperationsCounter.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("operation", operation), // "add" or "remove"
			attribute.String("reason", reason),
			attribute.Bool("permanent", permanent),
		),
	)
}

// BlacklistedPeerCount records the current number of blacklisted peers
func (nodeMetrics) BlacklistedPeerCount(ctx context.Context, count int) {
	blacklistedPeersGauge.Record(ctx, int64(count))
}

// AutoBlacklistEvent records an automatic blacklist event
func (nodeMetrics) AutoBlacklistEvent(ctx context.Context, reason string, attempts int64) {
	autoBlacklistCounter.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("reason", reason),
			attribute.Int64("attempts", attempts),
		),
	)
}

// BlockedConnection records a connection blocked due to blacklist
func (nodeMetrics) BlockedConnection(ctx context.Context, direction, reason string) {
	blacklistConnectionsBlocked.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("direction", direction), // "inbound" or "outbound"
			attribute.String("reason", reason),
		),
	)
}

type DBMetrics interface {
	AcquiredConnections(ctx context.Context, dbName string)
	ReleasedConnection(ctx context.Context)
	RecordQuery(ctx context.Context, crudType string, duration time.Duration)
	RecordQueryFailure(ctx context.Context, crudType string, err error)
}

type dbMetrics struct{}

// AcquiredConnections logs a new connection to the database
func (dbMetrics) AcquiredConnections(ctx context.Context, dbName string) {
	// include attribute for the db name
	dbConnsActive.Add(ctx, 1, metric.WithAttributes(attribute.String("db_name", dbName)))
}

// ReleasedConnection logs a connection to the database being released
func (dbMetrics) ReleasedConnection(ctx context.Context) {
	dbConnsActive.Add(ctx, -1)
}

func (dbMetrics) RecordQuery(ctx context.Context, crudType string, duration time.Duration) {
	dbQueryLatencyHist.Record(ctx, 1000*duration.Seconds(),
		metric.WithAttributes(
			attribute.String("type", crudType),
		),
	)
}

func (dbMetrics) RecordQueryFailure(ctx context.Context, crudType string, err error) {
	dbQueryErrorCount.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("type", crudType),
			attribute.String("error", err.Error()),
		),
	)
}

type consensusMetrics struct{}

func (consensusMetrics) RecordExecuted(ctx context.Context, latency time.Duration, height, numTxns int64) {
	latencyMS := latency.Seconds() * 1000
	execLatencyHist.Record(ctx, latencyMS, metric.WithAttributes(attribute.Int64("height", height), attribute.Int64("num_txns", numTxns)))
	execCounter.Add(ctx, 1, metric.WithAttributes(attribute.Int64("height", height), attribute.Float64("latency", latencyMS), attribute.Int64("num_txns", numTxns)))
}

func (consensusMetrics) RecordCommit(ctx context.Context, latency time.Duration, height int64) {
	latencyMS := latency.Seconds() * 1000
	commitLatencyHist.Record(ctx, latencyMS, metric.WithAttributes(attribute.Int64("height", height)))
	commitCounter.Add(ctx, 1, metric.WithAttributes(attribute.Int64("height", height), attribute.Float64("latency", latencyMS)))
}

type ConsensusMetrics interface {
	RecordCommit(ctx context.Context, latency time.Duration, height int64)
	RecordExecuted(ctx context.Context, latency time.Duration, height, numTxns int64)
}

type RPCMetrics interface {
	RecordRequest(ctx context.Context, method string, status int, latency time.Duration)
	// RecordLatency(ctx context.Context, method string, latency time.Duration)
}

type rpcMetrics struct{}

// RecordRequest logs a request count
func (rpcMetrics) RecordRequest(ctx context.Context, method string, status int, latency time.Duration) {
	requests.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("method", method),
			attribute.Int("status", status),
		),
	)
	latencyHist.Record(ctx, 1000*latency.Seconds(),
		metric.WithAttributes(attribute.String("method", method)),
	)
}
