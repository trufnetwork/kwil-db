package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/store"
)

// Log is a struct that represents a log instance
type Log struct {
	Height    int64
	Duration  time.Duration
	NumTxns   uint32
	TxsSz     int64
	BlkSz     int64
	Timestamp time.Time
}

type TestParams struct {
	ProposeTimeout time.Duration `json:"propose_timeout"`
	MaxBlockSize   int64         `json:"max_block_size"`
	Concurrency    int64         `json:"concurrency"`
	PayloadSize    int64         `json:"payload_size"`
}

type Metrics struct {
	TestParams

	NumBlocks      int64          `json:"num_blocks"`
	TestDuration   types.Duration `json:"test_duration"`
	TotalTxns      uint32         `json:"total_txns"`
	TotalTxnsSize  int64          `json:"total_txns_size"`
	TotalBlockSize int64          `json:"total_block_size"`

	MinBlockTime    types.Duration `json:"min_block_time"`
	MaxBlockTime    types.Duration `json:"max_block_time"`
	MedianBlockTime types.Duration `json:"median_block_time"`

	MinBlkSz int64   `json:"min_blk_sz"`
	MaxBlkSz int64   `json:"max_blk_sz"`
	AvgBlkSz float64 `json:"avg_blk_sz"`
	MedBlkSz float64 `json:"med_blk_sz"`

	// Metrics
	// Transactions per second
	TPS float64 `json:"tps"`
	// Transactions per block
	TPB float64 `json:"tpb"`

	// Blocks per minute
	BlockRate float64 `json:"block_rate"`
	// ExpectedBlockRate: 60/(ProposeTimeout + delta)
	ExpectedBlockRate float64 `json:"expected_block_rate"`
	// RelativeBlockRate: BlockRate / ExpectedBlockRate
	RelativeBlockRate float64 `json:"relative_block_rate"`

	// median(TxSize or BlockSize) * BlockRate * 24 * 60 / 1000
	DataIngressRate float64 `json:"data_ingress_rate"`
	// Expected BlockRate * BlockSize * 24 * 60 / 1000
	ThresholdIngress float64 `json:"threshold_ingress"`

	// AvgBlockSize / MaxBlockSize
	ThroughputUtilization float64 `json:"throughput_utilization"`
	// Avg time to finalize a block
	AvgFinality float64 `json:"avg_finality"`
}

func ExtractLogs(bstore string, startBlock int64, endBlock int64, logFile string) ([]Log, error) {
	// Extract logs from the blockstore

	bs, err := store.NewBlockStore(bstore)
	if err != nil {
		return nil, fmt.Errorf("failed to open blockstore: %w", err)
	}

	// ensure that the blockstore has the start and end blocks
	h, _, _, _ := bs.Best()
	if h < endBlock {
		return nil, fmt.Errorf("blockstore does not have the required blocks, highest block is %d, required %d", h, endBlock)
	}

	// Adjust the start and end blocks to avoid empty blocks which are not part of the stress test
	// height := startBlock
	// for height < endBlock {
	// 	_, blk, _, err := bs.GetByHeight(startBlock)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("failed to get start block: %w", err)
	// 	}

	// 	if blk.Header.NumTxns > 0 { // first non empty block, use this as start block
	// 		break
	// 	}
	// 	height++
	// }
	// startBlock = height

	// height = endBlock
	// for height > startBlock {
	// 	_, blk, _, err := bs.GetByHeight(height)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("failed to get end block: %w", err)
	// 	}
	// 	if blk.Header.NumTxns > 0 { // last non empty block, use this as end block
	// 		break
	// 	}
	// 	height--
	// }
	// endBlock = height

	if endBlock <= startBlock {
		return nil, fmt.Errorf("no blocks with txns found between %d and %d", startBlock, endBlock)
	}

	logs := make([]Log, endBlock-startBlock+1)

	_, blkPre, _, err := bs.GetByHeight(startBlock - 1)
	if err != nil {
		return nil, fmt.Errorf("failed to get start block: %w", err)
	}

	for idx := startBlock; idx <= endBlock; idx++ {
		_, blk, _, err := bs.GetByHeight(idx)
		if err != nil {
			return nil, fmt.Errorf("failed to get block: %w", err)
		}

		hdr := blk.Header

		txSize := int64(0)
		for _, tx := range blk.Txns {
			// TODO: should we only include the size of the payload here?
			// txSize += int64(len(tx.Bytes()))
			txSize += int64(len(tx.Body.Payload))
		}

		logs[idx-startBlock] = Log{
			Height:    hdr.Height,
			Duration:  hdr.Timestamp.Sub(blkPre.Header.Timestamp),
			NumTxns:   hdr.NumTxns,
			TxsSz:     txSize,
			BlkSz:     int64(len(types.EncodeBlock(blk))),
			Timestamp: hdr.Timestamp,
		}

		blkPre = blk
	}

	return logs, WriteLogs(logs, logFile)
}

// Write logs to the csv file
func WriteLogs(logs []Log, logFile string) error {
	// Write logs to the csv file
	cf, err := os.Create(logFile)
	if err != nil {
		return fmt.Errorf("failed to create csv file: %s %w", logFile, err)
	}

	w := csv.NewWriter(cf)
	err = w.WriteAll(toCSVRecords(logs))
	if err != nil {
		return fmt.Errorf("failed to write csv records: %w", err)
	}

	return nil
}

func toCSVRecords(logs []Log) [][]string {
	var res [][]string

	res = append(res, []string{"height", "timestamp", "blocktime", "num_txs", "txs_sz", "blk_sz"})
	for _, log := range logs {
		entry := []string{
			strconv.FormatInt(log.Height, 10),
			log.Timestamp.Format(time.RFC3339),
			log.Duration.String(),
			strconv.FormatUint(uint64(log.NumTxns), 10),
			strconv.FormatInt(log.TxsSz, 10),
			strconv.FormatInt(log.BlkSz, 10),
		}
		res = append(res, entry)
	}
	return res
}

/*
Metrics:

	Transactions Per Second (TPS):
	- Block Header:
		NumTxs
		TotalNumTxs/TotalTime(seconds)

	- Data Ingress Rate(Gb/day):
		AvgBlockSize * BlockRate * 24 * 60 /1000

	- Throughput Utilization:
		AvgBlockSize/MaxBlockSize
		rawBlockSizes from the block headers

	- Average Time to Finality(secs):
		Avg time it takes to finalize a block

	- Block times
		Logs to collect: block headers with timestamps from test start height to end height

	- Block Rate Per Minute:
		60/FinalityAvg
*/

func AnalyzeLogs(logs []Log, testParams TestParams) Metrics {
	// Analyze the logs
	var totalTxns uint32
	var totalTxnsSize int64
	var totalBlockSize int64

	startLog := logs[0]
	endLog := logs[len(logs)-1]

	numBlocks := endLog.Height - startLog.Height + 1
	testDuration := endLog.Timestamp.Sub(startLog.Timestamp)

	var blockTimes []time.Duration
	var blockSizes []int64

	for _, log := range logs {
		totalTxns += log.NumTxns
		totalTxnsSize += log.TxsSz
		totalBlockSize += log.BlkSz
		blockTimes = append(blockTimes, log.Duration)
		blockSizes = append(blockSizes, log.BlkSz)
	}

	// sort the block times and block sizes
	slices.Sort(blockTimes)
	slices.Sort(blockSizes)

	var medianBlkTime time.Duration
	var medianBlkSz float64
	if numBlocks%2 == 0 {
		medianBlkTime = (blockTimes[numBlocks/2] + blockTimes[numBlocks/2-1]) / 2
		medianBlkSz = float64(blockSizes[numBlocks/2]+blockSizes[numBlocks/2-1]) / 2
	} else {
		medianBlkTime = blockTimes[numBlocks/2]
		medianBlkSz = float64(blockSizes[numBlocks/2])
	}
	avgBlkSz := float64(totalBlockSize) / float64(numBlocks)

	delta := 200 * time.Millisecond
	blockRate := float64(numBlocks) / testDuration.Minutes()
	expectedBlockRate := 60 / (testParams.ProposeTimeout.Seconds() + delta.Seconds())

	tps := float64(totalTxns) / testDuration.Seconds()
	tpb := float64(totalTxns) / float64(numBlocks)

	// median(TxSize or BlockSize) * BlockRate * 24 * 60 / 1000
	dataIngressRate := float64(medianBlkSz*blockRate*24*60) / float64(1000)

	// thesholdIngress := expectedBlockRate * float64(testParams.MaxBlockSize) * 24 * 60 / 1000
	thresholdIngress := expectedBlockRate * float64(testParams.MaxBlockSize) * 24 * 60 / 1000
	throughput := float64(avgBlkSz) / float64(testParams.MaxBlockSize)

	metrics := Metrics{
		TestParams: TestParams{
			ProposeTimeout: testParams.ProposeTimeout,
			MaxBlockSize:   testParams.MaxBlockSize,
			Concurrency:    testParams.Concurrency,
			PayloadSize:    testParams.PayloadSize,
		},
		NumBlocks:      numBlocks,
		TestDuration:   types.Duration(testDuration),
		TotalTxns:      totalTxns,
		TotalTxnsSize:  totalTxnsSize,
		TotalBlockSize: totalBlockSize,

		MinBlockTime:    types.Duration(blockTimes[0]),
		MaxBlockTime:    types.Duration(blockTimes[len(blockTimes)-1]),
		MedianBlockTime: types.Duration(medianBlkTime),

		MinBlkSz: blockSizes[0],
		MaxBlkSz: blockSizes[len(blockSizes)-1],
		AvgBlkSz: avgBlkSz,
		MedBlkSz: medianBlkSz,

		TPS: tps,
		TPB: tpb,

		BlockRate:         blockRate,
		ExpectedBlockRate: expectedBlockRate,
		RelativeBlockRate: blockRate / expectedBlockRate,

		DataIngressRate:  dataIngressRate,
		ThresholdIngress: thresholdIngress,

		ThroughputUtilization: throughput,
		AvgFinality:           testDuration.Seconds() / float64(numBlocks),
	}

	// write metrics to a file
	return metrics
}

func WriteMetrics(metrics Metrics, metricsFile string, format string) error {
	// Write the metrics to a file
	switch format {
	case "csv":
		return toCSVMetrics(metrics, metricsFile)
	case "json":
		return toJSONMetrics(metrics, metricsFile)
	default:
		return fmt.Errorf("invalid format: %s", format)
	}
}

func toJSONMetrics(metrics Metrics, metricsFile string) error {
	// Write the metrics to a file
	mf, err := os.Create(metricsFile)
	if err != nil {
		return fmt.Errorf("failed to create csv file: %s %w", metricsFile, err)
	}

	bts, err := json.MarshalIndent(metrics, "", "    ")
	if err != nil {
		return fmt.Errorf("failed to marshal metrics: %w", err)
	}

	_, err = mf.Write(bts)
	if err != nil {
		return fmt.Errorf("failed to write metrics: %w", err)
	}

	return nil
}

func toCSVMetrics(metric Metrics, metricsFile string) error {
	mf, err := os.Create(metricsFile)
	if err != nil {
		return fmt.Errorf("failed to create csv file: %s %w", metricsFile, err)
	}

	var res [][]string
	res = append(res, []string{
		"propose_timeout",
		"max_block_size",
		"concurrency",
		"payload_size",
		"num_blocks",
		"test_duration",
		"total_txns",
		"total_txns_size",
		"total_block_size",
		"min_block_time",
		"max_block_time",
		"median_block_time",
		"min_blk_sz",
		"max_blk_sz",
		"avg_blk_sz",
		"med_blk_sz",
		"tps",
		"tpb",
		"block_rate",
		"expected_block_rate",
		"relative_block_rate",
		"data_ingress_rate",
		"threshold_ingress",
		"throughput_utilization",
		"avg_finality",
	})

	entry := []string{
		strconv.FormatInt(int64(metric.ProposeTimeout.Seconds()), 10),
		strconv.FormatInt(metric.MaxBlockSize, 10),
		strconv.FormatInt(metric.Concurrency, 10),
		strconv.FormatInt(metric.PayloadSize, 10),

		strconv.FormatInt(metric.NumBlocks, 10),
		metric.TestDuration.String(),
		strconv.FormatUint(uint64(metric.TotalTxns), 10),
		strconv.FormatInt(metric.TotalTxnsSize, 10),
		strconv.FormatInt(metric.TotalBlockSize, 10),

		metric.MinBlockTime.String(),
		metric.MaxBlockTime.String(),
		metric.MedianBlockTime.String(),
		strconv.FormatInt(metric.MinBlkSz, 10),
		strconv.FormatInt(metric.MaxBlkSz, 10),
		strconv.FormatFloat(metric.AvgBlkSz, 'f', -1, 64),
		strconv.FormatFloat(metric.MedBlkSz, 'f', -1, 64),

		strconv.FormatFloat(metric.TPS, 'f', -1, 64),
		strconv.FormatFloat(metric.TPB, 'f', -1, 64),
		strconv.FormatFloat(metric.BlockRate, 'f', -1, 64),
		strconv.FormatFloat(metric.ExpectedBlockRate, 'f', -1, 64),
		strconv.FormatFloat(metric.RelativeBlockRate, 'f', -1, 64),
		strconv.FormatFloat(metric.DataIngressRate, 'f', -1, 64),
		strconv.FormatFloat(metric.ThresholdIngress, 'f', -1, 64),
		strconv.FormatFloat(metric.ThroughputUtilization, 'f', -1, 64),
		strconv.FormatFloat(metric.AvgFinality, 'f', -1, 64),
	}
	res = append(res, entry)

	csv := csv.NewWriter(mf)
	err = csv.WriteAll(res)
	if err != nil {
		fmt.Printf("failed to write csv records: %v", err)
	}
	return nil
}
