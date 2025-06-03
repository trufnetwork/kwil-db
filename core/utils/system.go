package utils

import (
	"context"
	"fmt"
	"math"
	"runtime"
	"time"
)

// SystemInfo contains basic system information for logging and estimation purposes
type SystemInfo struct {
	CPUCount int    `json:"cpu_count"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
}

// GetSystemInfo returns basic system information
func GetSystemInfo() SystemInfo {
	return SystemInfo{
		CPUCount: runtime.NumCPU(),
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
	}
}

// FormatBytes converts bytes to human-readable format (e.g., "1.5 GB")
func FormatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// EstimateRestoreTime provides a rough time estimate for database restoration
func EstimateRestoreTime(sizeBytes uint64, cpuCount int) int {
	if sizeBytes == 0 {
		return 1
	}

	// Base throughput: ~1 MB/s for database restoration
	// This accounts for PostgreSQL operations: SQL parsing, transaction execution,
	// index maintenance, WAL writes, and ACID compliance overhead
	// Real-world data shows ~1.59 MB/s actual throughput for bulk restoration
	baseMBps := 1.0

	// CPU count has limited impact since restoration is I/O and PostgreSQL-bound
	// More cores provide diminishing returns for database operations
	cpuMultiplier := math.Min(1.0+float64(cpuCount-1)*0.05, 1.3) // Up to 1.3x improvement
	adjustedMBps := baseMBps * cpuMultiplier

	// Convert bytes to MB and calculate time in seconds
	sizeMB := float64(sizeBytes) / (1024 * 1024)
	estimatedSeconds := sizeMB / adjustedMBps

	// Convert to minutes, minimum 1 minute
	estimatedMinutes := int(estimatedSeconds / 60)
	if estimatedMinutes < 1 {
		estimatedMinutes = 1
	}

	return estimatedMinutes
}

// Logger interface for the monitoring function
type Logger interface {
	Warn(msg string, keyvals ...interface{})
	Info(msg string, keyvals ...interface{})
}

// MonitorRestoreProgress monitors database restoration progress and warns if it takes too long
// It starts a goroutine that checks elapsed time every minute and warns if restoration
// takes more than 4x the estimated time, suggesting possible issues.
func MonitorRestoreProgress(ctx context.Context, estimatedMinutes int, logger Logger) context.CancelFunc {
	monitorCtx, cancel := context.WithCancel(ctx)

	go func() {
		startTime := time.Now()
		estimatedDuration := time.Duration(estimatedMinutes) * time.Minute
		warningThreshold := estimatedDuration * 4
		checkInterval := time.Minute

		// Don't start checking until after the estimated time has passed
		initialDelay := estimatedDuration
		if initialDelay < time.Minute {
			initialDelay = time.Minute
		}

		logger.Info("Database restoration progress monitoring started",
			"estimated_duration", estimatedDuration,
			"warning_threshold", warningThreshold)

		// Wait for the initial delay before starting checks
		select {
		case <-monitorCtx.Done():
			return
		case <-time.After(initialDelay):
		}

		ticker := time.NewTicker(checkInterval)
		defer ticker.Stop()

		warningIssued := false

		for {
			select {
			case <-monitorCtx.Done():
				elapsed := time.Since(startTime)
				logger.Info("Database restoration monitoring stopped",
					"total_elapsed", elapsed,
					"estimated_duration", estimatedDuration)
				return
			case <-ticker.C:
				elapsed := time.Since(startTime)

				// Issue warning if we've exceeded 4x the estimated time and haven't warned yet
				if !warningIssued && elapsed > warningThreshold {
					warningIssued = true
					logger.Warn("Database restoration is taking significantly longer than expected. This may indicate an issue.",
						"elapsed_time", elapsed,
						"estimated_time", estimatedDuration,
						"threshold_exceeded", fmt.Sprintf("%.1fx longer than estimated", float64(elapsed)/float64(estimatedDuration)),
						"possible_causes", "slow disk I/O, PostgreSQL configuration issues, insufficient system resources, or data corruption",
						"suggestion", "Check system resources (disk I/O, CPU, memory) and PostgreSQL logs for errors")
				}

				// Provide periodic progress updates every 5 minutes after the warning threshold
				if warningIssued && int(elapsed.Minutes())%5 == 0 {
					logger.Info("Database restoration still in progress",
						"elapsed_time", elapsed,
						"times_over_estimate", fmt.Sprintf("%.1fx", float64(elapsed)/float64(estimatedDuration)))
				}
			}
		}
	}()

	return cancel
}
