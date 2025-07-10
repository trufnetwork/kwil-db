package interpreter

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestProfiler_DemoIntegration demonstrates the profiler working with the interpreter
func TestProfiler_DemoIntegration(t *testing.T) {
	// Create profiler configuration for demonstration
	config := DefaultProfilerConfig()
	config.Mode = ProfilerModeEnabled
	config.MinDurationThreshold = 0 // Include all operations

	profiler := NewProfiler(config)
	defer profiler.Close()

	// Create a profiled context
	ctx := WithProfiler(context.Background(), profiler)

	// Simulate interpreter operations
	t.Log("=== Simulating Kuneiform Procedure Execution ===")

	// 1. Action execution
	actionID := profiler.StartOperation("action", "create_user", map[string]interface{}{
		"namespace": "users",
		"params":    []string{"name", "email"},
	})

	// 2. Variable declaration and assignment
	declID := profiler.StartOperation("statement", "declaration", nil)
	time.Sleep(100 * time.Microsecond)
	profiler.EndOperation(declID, 0)

	// 3. Loop execution with SQL queries (demonstrating N+1 problem)
	loopID := profiler.StartOperation("loop", "validate_emails", nil)
	for i := 0; i < 10; i++ {
		profiler.RecordLoopIteration(loopID, int64(i+1))

		// SQL query for each iteration (bad pattern)
		sqlID := profiler.StartOperation("sql", "SELECT", map[string]interface{}{
			"query": fmt.Sprintf("SELECT COUNT(*) FROM users WHERE email = '%s'", fmt.Sprintf("user%d@example.com", i)),
		})
		time.Sleep(2 * time.Millisecond) // Simulate SQL execution time
		profiler.RecordSQLQuery(sqlID, fmt.Sprintf("SELECT COUNT(*) FROM users WHERE email = 'user%d@example.com'", i), 2*time.Millisecond)
		profiler.EndOperation(sqlID, 0)
	}
	profiler.EndOperation(loopID, 0)

	// 4. Function call
	funcID := profiler.StartOperation("function", "hash_password", map[string]interface{}{
		"algorithm": "bcrypt",
	})
	time.Sleep(5 * time.Millisecond)
	profiler.EndOperation(funcID, 0)

	// 5. Final SQL insert
	insertID := profiler.StartOperation("sql", "INSERT", map[string]interface{}{
		"query": "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
	})
	time.Sleep(3 * time.Millisecond)
	profiler.RecordSQLQuery(insertID, "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)", 3*time.Millisecond)
	profiler.EndOperation(insertID, 0)

	profiler.EndOperation(actionID, 0)

	// Generate comprehensive report
	reportConfig := DefaultReportConfig()
	reportConfig.IncludeCallStack = true
	reportConfig.IncludeMetadata = true
	reportConfig.TopN = 15

	report, err := profiler.GenerateDetailedReport(reportConfig)
	if err != nil {
		t.Fatalf("Failed to generate report: %v", err)
	}

	// Print the detailed report
	t.Log("\n=== PERFORMANCE ANALYSIS REPORT ===")
	t.Logf("Total Operations: %d", report.Summary.TotalOperations)
	t.Logf("Total Execution Time: %v", report.Summary.TotalTime)
	t.Logf("Average Time per Operation: %v\n", report.Summary.TotalTime/time.Duration(report.Summary.TotalOperations))

	// Print performance issues
	if len(report.PerformanceIssues) > 0 {
		t.Log("🚨 PERFORMANCE ISSUES DETECTED:")
		for _, issue := range report.PerformanceIssues {
			t.Logf("  [%s] %s: %s", strings.ToUpper(issue.Severity), issue.Operation, issue.Description)
		}
		t.Log("")
	}

	// Print top operations
	if len(report.TopOperations) > 0 {
		t.Log("⏱️  TOP OPERATIONS BY TIME:")
		for i, op := range report.TopOperations[:min(5, len(report.TopOperations))] {
			pct := float64(op.TotalTime) / float64(report.Summary.TotalTime) * 100
			t.Logf("  %d. %s.%s: %v (%.1f%%) - %d calls",
				i+1, op.Type, op.Name, op.TotalTime, pct, op.Count)
		}
		t.Log("")
	}

	// Print recommendations
	if len(report.Recommendations) > 0 {
		t.Log("💡 PERFORMANCE RECOMMENDATIONS:")
		for i, rec := range report.Recommendations {
			t.Logf("  %d. %s", i+1, rec)
		}
		t.Log("")
	}

	// Verify that we detected the SQL in loop issue
	foundSQLInLoop := false
	for _, issue := range report.PerformanceIssues {
		if issue.Type == "sql_in_loop" {
			foundSQLInLoop = true
			break
		}
	}

	if !foundSQLInLoop {
		t.Error("Expected to detect SQL in loop performance issue (N+1 problem)")
	}

	// Generate simple text report for comparison
	textReport := profiler.GenerateReport()
	t.Log("=== SIMPLE TEXT REPORT ===")
	t.Log(textReport)

	// Test profiler from context retrieval
	retrievedProfiler := ProfilerFromContext(ctx)
	if retrievedProfiler != profiler {
		t.Error("Failed to retrieve profiler from context")
	}
}

// min is a helper function to get the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestProfiler_RealWorldScenario tests a realistic Kuneiform procedure scenario
func TestProfiler_RealWorldScenario(t *testing.T) {
	// Setup profiler
	config := DefaultProfilerConfig()
	config.Mode = ProfilerModeEnabled
	config.MinDurationThreshold = 0

	profiler := NewProfiler(config)
	defer profiler.Close()

	// Simulate a real-world procedure: "process_order"
	actionID := profiler.StartOperation("action", "process_order", map[string]interface{}{
		"namespace": "ecommerce",
		"order_id":  12345,
	})

	// Step 1: Validate order
	validateID := profiler.StartOperation("function", "validate_order", nil)
	time.Sleep(1 * time.Millisecond)
	profiler.EndOperation(validateID, 0)

	// Step 2: Check inventory for each item (N+1 problem)
	checkInventoryID := profiler.StartOperation("loop", "check_inventory", nil)
	for i := 0; i < 15; i++ { // 15 items in the order
		profiler.RecordLoopIteration(checkInventoryID, int64(i+1))

		// Individual SQL query for each item
		sqlID := profiler.StartOperation("sql", "SELECT", map[string]interface{}{
			"query": "SELECT quantity FROM inventory WHERE product_id = ?",
		})
		time.Sleep(800 * time.Microsecond)
		profiler.RecordSQLQuery(sqlID, "SELECT quantity FROM inventory WHERE product_id = ?", 800*time.Microsecond)
		profiler.EndOperation(sqlID, 0)
	}
	profiler.EndOperation(checkInventoryID, 0)

	// Step 3: Calculate taxes and shipping
	calcID := profiler.StartOperation("function", "calculate_totals", nil)
	time.Sleep(2 * time.Millisecond)
	profiler.EndOperation(calcID, 0)

	// Step 4: Process payment
	paymentID := profiler.StartOperation("action", "process_payment", nil)
	time.Sleep(10 * time.Millisecond) // Payment processing takes time
	profiler.EndOperation(paymentID, 0)

	// Step 5: Update inventory (batch operation)
	updateID := profiler.StartOperation("sql", "UPDATE", map[string]interface{}{
		"query": "UPDATE inventory SET quantity = quantity - ? WHERE product_id = ?",
	})
	time.Sleep(5 * time.Millisecond)
	profiler.RecordSQLQuery(updateID, "UPDATE inventory SET quantity = quantity - ? WHERE product_id = ?", 5*time.Millisecond)
	profiler.EndOperation(updateID, 0)

	// Step 6: Create order record
	insertOrderID := profiler.StartOperation("sql", "INSERT", map[string]interface{}{
		"query": "INSERT INTO orders (customer_id, total, status) VALUES (?, ?, ?)",
	})
	time.Sleep(2 * time.Millisecond)
	profiler.RecordSQLQuery(insertOrderID, "INSERT INTO orders (customer_id, total, status) VALUES (?, ?, ?)", 2*time.Millisecond)
	profiler.EndOperation(insertOrderID, 0)

	profiler.EndOperation(actionID, 0)

	// Generate and analyze report
	report, err := profiler.GenerateDetailedReport(DefaultReportConfig())
	if err != nil {
		t.Fatalf("Failed to generate report: %v", err)
	}

	t.Logf("Real-world scenario analysis:")
	t.Logf("- Total operations: %d", report.Summary.TotalOperations)
	t.Logf("- Total time: %v", report.Summary.TotalTime)
	t.Logf("- Performance issues: %d", len(report.PerformanceIssues))

	// Should detect SQL in loop issue
	foundN1Problem := false
	for _, issue := range report.PerformanceIssues {
		if issue.Type == "sql_in_loop" {
			foundN1Problem = true
			t.Logf("✅ Detected N+1 problem: %s", issue.Description)
		}
	}

	if !foundN1Problem {
		t.Error("Expected to detect N+1 problem in inventory checking")
	}

	// Verify we have the right recommendations
	hasOptimizationRec := false
	for _, rec := range report.Recommendations {
		if strings.Contains(strings.ToLower(rec), "batch") || strings.Contains(strings.ToLower(rec), "join") {
			hasOptimizationRec = true
			t.Logf("✅ Good recommendation: %s", rec)
		}
	}

	if !hasOptimizationRec {
		t.Error("Expected optimization recommendations for the N+1 problem")
	}
}

// TestProfiler_DisabledPerformance verifies zero overhead when disabled
func TestProfiler_DisabledPerformance(t *testing.T) {
	// Test with disabled profiler
	config := DefaultProfilerConfig()
	config.Mode = ProfilerModeDisabled

	profiler := NewProfiler(config)
	defer profiler.Close()

	// These operations should be no-ops
	start := time.Now()
	for i := 0; i < 1000; i++ {
		id := profiler.StartOperation("test", "operation", nil)
		profiler.RecordSQLQuery(id, "SELECT 1", time.Microsecond)
		profiler.RecordLoopIteration(id, int64(i))
		profiler.EndOperation(id, 0)
	}
	elapsed := time.Since(start)

	// Should complete very quickly
	if elapsed > 1*time.Millisecond {
		t.Errorf("Disabled profiler took too long: %v", elapsed)
	}

	// Should have no entries
	entries := profiler.GetEntries()
	if len(entries) != 0 {
		t.Errorf("Disabled profiler should have no entries, got %d", len(entries))
	}

	// Report should indicate disabled
	report := profiler.GenerateReport()
	if !strings.Contains(report, "disabled") {
		t.Error("Report should indicate profiling is disabled")
	}

	t.Logf("✅ Disabled profiler completed 1000 operations in %v (excellent performance)", elapsed)
}
