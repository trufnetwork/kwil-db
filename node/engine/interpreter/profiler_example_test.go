package interpreter

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// ExampleProfiler demonstrates basic profiler usage
func ExampleProfiler() {
	// Create profiler configuration
	config := DefaultProfilerConfig()
	config.Mode = ProfilerModeEnabled
	config.EnableSQLProfiling = true
	config.EnableLoopProfiling = true
	config.EnableActionProfiling = true
	
	// Create profiler
	profiler := NewProfiler(config)
	defer profiler.Close()
	
	// Profile an action execution
	actionID := profiler.StartOperation("action", "create_user", map[string]interface{}{
		"namespace": "users",
	})
	
	// Simulate some SQL operations within the action
	sqlID := profiler.StartOperation("sql", "INSERT", map[string]interface{}{
		"query": "INSERT INTO users (name, email) VALUES (?, ?)",
	})
	time.Sleep(10 * time.Millisecond)
	profiler.EndOperation(sqlID, 0)
	
	// Simulate a loop
	loopID := profiler.StartOperation("loop", "validation", nil)
	for i := 0; i < 5; i++ {
		profiler.RecordLoopIteration(loopID, int64(i+1))
		time.Sleep(2 * time.Millisecond)
	}
	profiler.EndOperation(loopID, 0)
	
	profiler.EndOperation(actionID, 0)
	
	// Generate and print report
	report := profiler.GenerateReport()
	fmt.Println(report)
	
	// Output will contain profiling information
}

// TestExampleProfiledTestRunner demonstrates how to use the profiled test runner
func TestExampleProfiledTestRunner(t *testing.T) {
	// Setup profiler configuration
	profilerConfig := DefaultProfilerConfig()
	profilerConfig.Mode = ProfilerModeEnabled
	
	reportConfig := DefaultReportConfig()
	reportConfig.TopN = 5
	
	// Create test runner
	runner := NewProfiledTestRunner(profilerConfig, reportConfig, "/tmp/kwil_profiles")
	
	// Define test functions
	tests := map[string]func(context.Context) error{
		"test_user_creation": func(ctx context.Context) error {
			profiler := ProfilerFromContext(ctx)
			if profiler != nil {
				id := profiler.StartOperation("action", "create_user", nil)
				defer profiler.EndOperation(id, 0)
				
				// Simulate SQL operations
				sqlID := profiler.StartOperation("sql", "INSERT", nil)
				time.Sleep(5 * time.Millisecond)
				profiler.EndOperation(sqlID, 0)
			}
			return nil
		},
		"test_data_query": func(ctx context.Context) error {
			profiler := ProfilerFromContext(ctx)
			if profiler != nil {
				id := profiler.StartOperation("action", "query_data", nil)
				defer profiler.EndOperation(id, 0)
				
				// Simulate multiple SQL queries (potential N+1 problem)
				for i := 0; i < 10; i++ {
					sqlID := profiler.StartOperation("sql", "SELECT", nil)
					time.Sleep(2 * time.Millisecond)
					profiler.EndOperation(sqlID, 0)
				}
			}
			return nil
		},
	}
	
	// Run test suite
	suite, err := runner.RunProfiledTestSuite(context.Background(), "user_management", tests)
	if err != nil {
		fmt.Printf("Error running test suite: %v\n", err)
		return
	}
	
	// Print suite summary
	fmt.Printf("Test Suite: %s\n", suite.Name)
	fmt.Printf("Total Tests: %d\n", suite.Summary.TotalTests)
	fmt.Printf("Passed: %d\n", suite.Summary.PassedTests)
	fmt.Printf("Failed: %d\n", suite.Summary.FailedTests)
	fmt.Printf("Total Time: %v\n", suite.Summary.TotalTime)
	fmt.Printf("Performance Issues: %d\n", suite.Summary.PerformanceIssues)
}

// TestProfiler_RealisticScenario tests a realistic database operation scenario
func TestProfiler_RealisticScenario(t *testing.T) {
	config := DefaultProfilerConfig()
	config.Mode = ProfilerModeEnabled
	config.EnableSQLProfiling = true
	config.EnableLoopProfiling = true
	config.EnableActionProfiling = true
	
	profiler := NewProfiler(config)
	defer profiler.Close()
	
	// Simulate a complex action that performs multiple operations
	actionID := profiler.StartOperation("action", "process_user_data", map[string]interface{}{
		"namespace": "users",
		"action":    "process_user_data",
	})
	
	// 1. Validation loop
	validationID := profiler.StartOperation("loop", "validate_users", nil)
	for i := 0; i < 50; i++ {
		profiler.RecordLoopIteration(validationID, int64(i+1))
		time.Sleep(100 * time.Microsecond) // Small delay to simulate validation work
	}
	profiler.EndOperation(validationID, 0)
	
	// 2. Database operations
	for i := 0; i < 5; i++ {
		sqlID := profiler.StartOperation("sql", "SELECT", map[string]interface{}{
			"query": fmt.Sprintf("SELECT * FROM users WHERE department_id = %d", i+1),
		})
		time.Sleep(8 * time.Millisecond) // Simulate SQL execution time
		profiler.RecordSQLQuery(sqlID, fmt.Sprintf("SELECT * FROM users WHERE department_id = %d", i+1), 8*time.Millisecond)
		profiler.EndOperation(sqlID, 0)
	}
	
	// 3. Data processing loop with nested SQL (N+1 problem simulation)
	processingID := profiler.StartOperation("loop", "process_each_user", nil)
	for i := 0; i < 20; i++ {
		profiler.RecordLoopIteration(processingID, int64(i+1))
		
		// SQL query for each user (bad pattern)
		sqlID := profiler.StartOperation("sql", "SELECT", map[string]interface{}{
			"query": fmt.Sprintf("SELECT profile FROM user_profiles WHERE user_id = %d", i+1),
		})
		time.Sleep(3 * time.Millisecond)
		profiler.RecordSQLQuery(sqlID, fmt.Sprintf("SELECT profile FROM user_profiles WHERE user_id = %d", i+1), 3*time.Millisecond)
		profiler.EndOperation(sqlID, 0)
	}
	profiler.EndOperation(processingID, 0)
	
	// 4. Batch update
	batchID := profiler.StartOperation("sql", "UPDATE", map[string]interface{}{
		"query": "UPDATE users SET last_processed = NOW() WHERE id IN (...)",
	})
	time.Sleep(15 * time.Millisecond)
	profiler.RecordSQLQuery(batchID, "UPDATE users SET last_processed = NOW() WHERE id IN (...)", 15*time.Millisecond)
	profiler.EndOperation(batchID, 0)
	
	profiler.EndOperation(actionID, 0)
	
	// Generate comprehensive report
	reportConfig := DefaultReportConfig()
	reportConfig.IncludeCallStack = true
	reportConfig.IncludeMetadata = true
	reportConfig.TopN = 10
	
	report, err := profiler.GenerateDetailedReport(reportConfig)
	if err != nil {
		t.Fatalf("Failed to generate report: %v", err)
	}
	
	// Verify the report contains expected information
	if report.Summary.TotalOperations == 0 {
		t.Error("Expected operations to be recorded")
	}
	
	// Check for performance issues (should detect SQL in loop)
	foundSQLInLoop := false
	for _, issue := range report.PerformanceIssues {
		if issue.Type == "sql_in_loop" {
			foundSQLInLoop = true
			break
		}
	}
	
	if !foundSQLInLoop {
		t.Error("Expected to detect SQL in loop performance issue")
	}
	
	// Verify recommendations
	if len(report.Recommendations) == 0 {
		t.Error("Expected performance recommendations to be generated")
	}
	
	// Check for N+1 recommendation
	foundN1Recommendation := false
	for _, rec := range report.Recommendations {
		if strings.Contains(strings.ToLower(rec), "n+1") || strings.Contains(strings.ToLower(rec), "batch") {
			foundN1Recommendation = true
			break
		}
	}
	
	if !foundN1Recommendation {
		t.Error("Expected recommendation about N+1 problem")
	}
	
	// Print report for manual inspection
	t.Logf("Performance Report:\n%s", profiler.GenerateReport())
}

// TestProfiler_ReportFormats tests different report output formats
func TestProfiler_ReportFormats(t *testing.T) {
	config := DefaultProfilerConfig()
	config.Mode = ProfilerModeEnabled
	
	profiler := NewProfiler(config)
	defer profiler.Close()
	
	// Add some sample operations
	for i := 0; i < 3; i++ {
		id := profiler.StartOperation("test", fmt.Sprintf("operation_%d", i), map[string]interface{}{
			"index": i,
		})
		time.Sleep(time.Duration(i+1) * 5 * time.Millisecond)
		profiler.EndOperation(id, 0)
	}
	
	// Test different report formats
	formats := []ReportFormat{
		ReportFormatText,
		ReportFormatJSON,
		ReportFormatCSV,
		ReportFormatHTML,
	}
	
	for _, format := range formats {
		reportConfig := DefaultReportConfig()
		reportConfig.Format = format
		
		// Create temporary file
		tmpFile, err := os.CreateTemp("", fmt.Sprintf("kwil_profile_test_*.%s", format))
		if err != nil {
			t.Fatalf("Failed to create temp file: %v", err)
		}
		defer os.Remove(tmpFile.Name())
		defer tmpFile.Close()
		
		// Write report
		err = profiler.WriteReport(tmpFile, reportConfig)
		if err != nil {
			t.Errorf("Failed to write %s report: %v", format, err)
			continue
		}
		
		// Verify file was written
		info, err := tmpFile.Stat()
		if err != nil {
			t.Errorf("Failed to stat %s report file: %v", format, err)
			continue
		}
		
		if info.Size() == 0 {
			t.Errorf("Report file for format %s is empty", format)
		}
		
		t.Logf("Successfully generated %s report (%d bytes)", format, info.Size())
	}
}

// BenchmarkProfiler_PerformanceImpact measures the performance impact of profiling
func BenchmarkProfiler_PerformanceImpact(b *testing.B) {
	// Test with profiler disabled
	b.Run("Disabled", func(b *testing.B) {
		config := DefaultProfilerConfig()
		config.Mode = ProfilerModeDisabled
		profiler := NewProfiler(config)
		defer profiler.Close()
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			id := profiler.StartOperation("test", "operation", nil)
			profiler.EndOperation(id, 0)
		}
	})
	
	// Test with profiler enabled
	b.Run("Enabled", func(b *testing.B) {
		config := DefaultProfilerConfig()
		config.Mode = ProfilerModeEnabled
		profiler := NewProfiler(config)
		defer profiler.Close()
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			id := profiler.StartOperation("test", "operation", nil)
			profiler.EndOperation(id, 0)
		}
	})
	
	// Test with detailed profiling
	b.Run("Detailed", func(b *testing.B) {
		config := DefaultProfilerConfig()
		config.Mode = ProfilerModeDetailed
		config.EnableSQLProfiling = true
		config.EnableLoopProfiling = true
		config.EnableActionProfiling = true
		config.EnableFunctionProfiling = true
		profiler := NewProfiler(config)
		defer profiler.Close()
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			id := profiler.StartOperation("test", "operation", map[string]interface{}{
				"iteration": i,
				"metadata":  "test_data",
			})
			profiler.RecordLoopIteration(id, int64(i))
			profiler.RecordSQLQuery(id, "SELECT * FROM test", time.Microsecond)
			profiler.EndOperation(id, 0)
		}
	})
}