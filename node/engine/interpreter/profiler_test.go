package interpreter

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestProfiler_BasicFunctionality(t *testing.T) {
	config := DefaultProfilerConfig()
	config.Mode = ProfilerModeEnabled
	
	profiler := NewProfiler(config)
	defer profiler.Close()
	
	if !profiler.IsEnabled() {
		t.Fatal("Expected profiler to be enabled")
	}
	
	// Test operation profiling
	metadata := map[string]interface{}{"test": "value"}
	id := profiler.StartOperation("test", "operation1", metadata)
	
	if id == "" {
		t.Fatal("Expected non-empty operation ID")
	}
	
	// Simulate some work
	time.Sleep(10 * time.Millisecond)
	
	profiler.EndOperation(id, 0)
	
	// Check entries
	entries := profiler.GetEntries()
	if len(entries) != 1 {
		t.Fatalf("Expected 1 entry, got %d", len(entries))
	}
	
	entry := entries[0]
	if entry.Type != "test" {
		t.Errorf("Expected type 'test', got '%s'", entry.Type)
	}
	if entry.Name != "operation1" {
		t.Errorf("Expected name 'operation1', got '%s'", entry.Name)
	}
	if entry.Duration <= 0 {
		t.Errorf("Expected positive duration, got %v", entry.Duration)
	}
	
	// Test summary generation
	summary := profiler.GetSummary()
	if summary == nil {
		t.Fatal("Expected non-nil summary")
	}
	if summary.TotalOperations != 1 {
		t.Errorf("Expected 1 total operation, got %d", summary.TotalOperations)
	}
}

func TestProfiler_NestedOperations(t *testing.T) {
	config := DefaultProfilerConfig()
	config.Mode = ProfilerModeEnabled
	config.MinDurationThreshold = 0 // Include all operations
	
	profiler := NewProfiler(config)
	defer profiler.Close()
	
	// Start parent operation
	parentID := profiler.StartOperation("parent", "operation1", nil)
	time.Sleep(1 * time.Millisecond)
	
	// Start child operation
	childID := profiler.StartOperation("child", "operation2", nil)
	time.Sleep(1 * time.Millisecond)
	
	// End child operation
	profiler.EndOperation(childID, 0)
	
	// End parent operation
	profiler.EndOperation(parentID, 0)
	
	// Check entries
	entries := profiler.GetEntries()
	if len(entries) != 2 {
		t.Fatalf("Expected 2 entries, got %d", len(entries))
	}
	
	// Find parent and child entries
	var parent, child *ProfileEntry
	for i := range entries {
		if entries[i].ID == parentID {
			parent = &entries[i]
		} else if entries[i].ID == childID {
			child = &entries[i]
		}
	}
	
	if parent == nil || child == nil {
		t.Fatal("Could not find parent or child entry")
	}
	
	if child.ParentID != parentID {
		t.Errorf("Expected child parent ID to be %s, got %s", parentID, child.ParentID)
	}
	
	if child.Depth != parent.Depth+1 {
		t.Errorf("Expected child depth to be %d, got %d", parent.Depth+1, child.Depth)
	}
}

func TestProfiler_DisabledMode(t *testing.T) {
	config := DefaultProfilerConfig()
	config.Mode = ProfilerModeDisabled
	
	profiler := NewProfiler(config)
	defer profiler.Close()
	
	if profiler.IsEnabled() {
		t.Fatal("Expected profiler to be disabled")
	}
	
	// Operations should be no-ops
	id := profiler.StartOperation("test", "operation1", nil)
	if id != "" {
		t.Errorf("Expected empty ID for disabled profiler, got %s", id)
	}
	
	profiler.EndOperation(id, 0)
	
	entries := profiler.GetEntries()
	if len(entries) != 0 {
		t.Errorf("Expected 0 entries for disabled profiler, got %d", len(entries))
	}
}

func TestProfiler_LoopIteration(t *testing.T) {
	config := DefaultProfilerConfig()
	config.Mode = ProfilerModeEnabled
	config.EnableLoopProfiling = true
	config.MinDurationThreshold = 0 // Include all operations
	
	profiler := NewProfiler(config)
	defer profiler.Close()
	
	id := profiler.StartOperation("loop", "for_loop", nil)
	
	// Simulate loop iterations
	for i := 0; i < 5; i++ {
		profiler.RecordLoopIteration(id, int64(i+1))
		time.Sleep(100 * time.Microsecond) // Small delay to ensure duration
	}
	
	profiler.EndOperation(id, 0)
	
	entries := profiler.GetEntries()
	if len(entries) != 1 {
		t.Fatalf("Expected 1 entry, got %d", len(entries))
	}
	
	entry := entries[0]
	if entry.LoopCount != 5 {
		t.Errorf("Expected loop count 5, got %d", entry.LoopCount)
	}
}

func TestProfiler_SQLQuery(t *testing.T) {
	config := DefaultProfilerConfig()
	config.Mode = ProfilerModeEnabled
	config.EnableSQLProfiling = true
	config.MinDurationThreshold = 0 // Include all operations
	
	profiler := NewProfiler(config)
	defer profiler.Close()
	
	id := profiler.StartOperation("sql", "query", nil)
	time.Sleep(1 * time.Millisecond) // Ensure some duration
	
	// Record SQL query
	query := "SELECT * FROM users WHERE id = ?"
	duration := 25 * time.Millisecond
	profiler.RecordSQLQuery(id, query, duration)
	
	profiler.EndOperation(id, 0)
	
	entries := profiler.GetEntries()
	if len(entries) != 1 {
		t.Fatalf("Expected 1 entry, got %d", len(entries))
	}
	
	entry := entries[0]
	if entry.SQLQuery != query {
		t.Errorf("Expected SQL query '%s', got '%s'", query, entry.SQLQuery)
	}
	
	if entry.Metadata["sql_duration"] != duration {
		t.Errorf("Expected SQL duration %v, got %v", duration, entry.Metadata["sql_duration"])
	}
}

func TestProfiler_ReportGeneration(t *testing.T) {
	config := DefaultProfilerConfig()
	config.Mode = ProfilerModeEnabled
	
	profiler := NewProfiler(config)
	defer profiler.Close()
	
	// Add some test operations
	for i := 0; i < 3; i++ {
		id := profiler.StartOperation("test", "operation", nil)
		time.Sleep(5 * time.Millisecond)
		profiler.EndOperation(id, 0)
	}
	
	// Generate text report
	report := profiler.GenerateReport()
	if report == "" {
		t.Fatal("Expected non-empty text report")
	}
	
	if !strings.Contains(report, "Total Operations: 3") {
		t.Error("Report should contain total operations count")
	}
	
	if !strings.Contains(report, "test.operation") {
		t.Error("Report should contain operation details")
	}
}

func TestProfiler_PerformanceThresholds(t *testing.T) {
	config := DefaultProfilerConfig()
	config.Mode = ProfilerModeEnabled
	config.MinDurationThreshold = 10 * time.Millisecond
	
	profiler := NewProfiler(config)
	defer profiler.Close()
	
	// Add fast operation (should be filtered out)
	fastID := profiler.StartOperation("test", "fast", nil)
	time.Sleep(1 * time.Millisecond)
	profiler.EndOperation(fastID, 0)
	
	// Add slow operation (should be included)
	slowID := profiler.StartOperation("test", "slow", nil)
	time.Sleep(15 * time.Millisecond)
	profiler.EndOperation(slowID, 0)
	
	entries := profiler.GetEntries()
	if len(entries) != 1 {
		t.Fatalf("Expected 1 entry after filtering, got %d", len(entries))
	}
	
	if entries[0].Name != "slow" {
		t.Errorf("Expected 'slow' operation to remain, got '%s'", entries[0].Name)
	}
}

func TestProfiler_MaxEntries(t *testing.T) {
	config := DefaultProfilerConfig()
	config.Mode = ProfilerModeEnabled
	config.MaxEntries = 2
	
	profiler := NewProfiler(config)
	defer profiler.Close()
	
	// Add 3 operations, but only 2 should be stored
	for i := 0; i < 3; i++ {
		id := profiler.StartOperation("test", "operation", nil)
		profiler.EndOperation(id, 0)
	}
	
	// Should get empty IDs for operations beyond the limit
	summary := profiler.GetSummary()
	if summary.TotalOperations > 2 {
		t.Errorf("Expected at most 2 operations, got %d", summary.TotalOperations)
	}
}

func TestProfiler_ContextIntegration(t *testing.T) {
	config := DefaultProfilerConfig()
	config.Mode = ProfilerModeEnabled
	
	profiler := NewProfiler(config)
	defer profiler.Close()
	
	// Test context integration
	ctx := context.Background()
	profiledCtx := WithProfiler(ctx, profiler)
	
	retrievedProfiler := ProfilerFromContext(profiledCtx)
	if retrievedProfiler != profiler {
		t.Error("Expected to retrieve the same profiler from context")
	}
	
	// Test with nil context
	nilProfiler := ProfilerFromContext(context.Background())
	if nilProfiler != nil {
		t.Error("Expected nil profiler from context without profiler")
	}
}

func TestProfiledTestRunner_BasicTest(t *testing.T) {
	config := DefaultProfilerConfig()
	config.Mode = ProfilerModeEnabled
	
	reportConfig := DefaultReportConfig()
	runner := NewProfiledTestRunner(config, reportConfig, "")
	
	// Define a simple test function
	testFunc := func(ctx context.Context) error {
		profiler := ProfilerFromContext(ctx)
		if profiler == nil {
			t.Error("Expected profiler in context")
			return nil
		}
		
		// Simulate some work
		id := profiler.StartOperation("test", "work", nil)
		time.Sleep(5 * time.Millisecond)
		profiler.EndOperation(id, 0)
		
		return nil
	}
	
	// Run the profiled test
	result, err := runner.RunProfiledTest(context.Background(), "basic_test", testFunc)
	if err != nil {
		t.Fatalf("Failed to run profiled test: %v", err)
	}
	
	if !result.Success {
		t.Error("Expected test to succeed")
	}
	
	if result.TestName != "basic_test" {
		t.Errorf("Expected test name 'basic_test', got '%s'", result.TestName)
	}
	
	if result.ProfileReport == nil {
		t.Error("Expected profile report to be generated")
	}
	
	if result.PerformanceMetrics == nil {
		t.Error("Expected performance metrics to be calculated")
	}
}

func TestProfiler_PerformanceIssueDetection(t *testing.T) {
	config := DefaultProfilerConfig()
	config.Mode = ProfilerModeEnabled
	config.MinDurationThreshold = 0 // Include all operations
	
	profiler := NewProfiler(config)
	defer profiler.Close()
	
	// Add a slow operation
	id := profiler.StartOperation("test", "slow_operation", nil)
	time.Sleep(150 * time.Millisecond) // Exceeds the 100ms threshold
	profiler.EndOperation(id, 0)
	
	// Add a high iteration loop
	loopID := profiler.StartOperation("loop", "high_iteration", nil)
	profiler.RecordLoopIteration(loopID, 1500) // Exceeds the 1000 threshold
	profiler.EndOperation(loopID, 0)
	
	// Generate report with performance issues
	reportConfig := DefaultReportConfig()
	report, err := profiler.GenerateDetailedReport(reportConfig)
	if err != nil {
		t.Fatalf("Failed to generate report: %v", err)
	}
	
	if len(report.PerformanceIssues) == 0 {
		t.Error("Expected performance issues to be detected")
	}
	
	// Debug output
	t.Logf("Found %d performance issues:", len(report.PerformanceIssues))
	for _, issue := range report.PerformanceIssues {
		t.Logf("- Type: %s, Operation: %s, Description: %s", issue.Type, issue.Operation, issue.Description)
	}
	
	// Check for slow operation issue
	foundSlowOp := false
	foundHighLoop := false
	for _, issue := range report.PerformanceIssues {
		if issue.Type == "slow_operation" {
			foundSlowOp = true
		}
		if issue.Type == "high_iteration_loop" {
			foundHighLoop = true
		}
	}
	
	if !foundSlowOp {
		t.Error("Expected slow operation issue to be detected")
	}
	if !foundHighLoop {
		t.Error("Expected high iteration loop issue to be detected")
	}
}