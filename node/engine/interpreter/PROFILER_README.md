# Kwil Interpreter Performance Profiler

## Overview

The Kwil Interpreter Performance Profiler is a comprehensive tool designed to identify and analyze performance bottlenecks in Kuneiform procedure executions. It provides detailed insights into SQL query performance, loop iterations, action calls, and function executions with minimal performance impact when disabled.

## Key Features

- **Zero-overhead when disabled**: No performance impact when profiling is turned off
- **Comprehensive coverage**: Profiles SQL queries, loops, actions, and function calls
- **Performance issue detection**: Automatically identifies common performance problems
- **Multiple report formats**: Text, JSON, CSV, and HTML reports
- **Testing framework integration**: Easy integration with Kwil testing infrastructure
- **Actionable recommendations**: Provides specific suggestions for performance improvements

## Quick Start

### Basic Usage

```go
import "github.com/trufnetwork/kwil-db/node/engine/interpreter"

// Create profiler configuration
config := interpreter.DefaultProfilerConfig()
config.Mode = interpreter.ProfilerModeEnabled
config.EnableSQLProfiling = true
config.EnableLoopProfiling = true

// Create profiler
profiler := interpreter.NewProfiler(config)
defer profiler.Close()

// Add profiler to context
ctx := interpreter.WithProfiler(context.Background(), profiler)

// Execute your Kuneiform procedures with the profiled context
// ...

// Generate performance report
report := profiler.GenerateReport()
fmt.Println(report)
```

### Integration with Testing

```go
// Setup profiled test runner
profilerConfig := interpreter.DefaultProfilerConfig()
profilerConfig.Mode = interpreter.ProfilerModeEnabled

reportConfig := interpreter.DefaultReportConfig()
runner := interpreter.NewProfiledTestRunner(profilerConfig, reportConfig, "./profiling_reports")

// Define test function
testFunc := func(ctx context.Context) error {
    // Your test logic here
    return nil
}

// Run profiled test
result, err := runner.RunProfiledTest(context.Background(), "my_test", testFunc)
if err != nil {
    log.Fatalf("Test failed: %v", err)
}

// Access profiling results
fmt.Printf("Test completed in %v\n", result.ExecutionTime)
fmt.Printf("Performance issues found: %d\n", len(result.ProfileReport.PerformanceIssues))
```

## Configuration

### ProfilerConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Mode` | `ProfilerMode` | `ProfilerModeDisabled` | Profiling mode (Disabled/Enabled/Detailed) |
| `EnableSQLProfiling` | `bool` | `true` | Profile SQL query execution |
| `EnableLoopProfiling` | `bool` | `true` | Profile loop iterations |
| `EnableActionProfiling` | `bool` | `true` | Profile action calls |
| `EnableFunctionProfiling` | `bool` | `true` | Profile function calls |
| `MinDurationThreshold` | `time.Duration` | `1ms` | Minimum duration to include in reports |
| `MaxEntries` | `int` | `10000` | Maximum number of profiling entries to store |

### ProfilerReportConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Format` | `ReportFormat` | `ReportFormatText` | Output format (Text/JSON/CSV/HTML) |
| `IncludeCallStack` | `bool` | `false` | Include hierarchical call stack |
| `IncludeMetadata` | `bool` | `true` | Include operation metadata |
| `TopN` | `int` | `20` | Number of top operations to show |
| `MinDuration` | `time.Duration` | `1ms` | Minimum duration for inclusion |

## Profiler Modes

### ProfilerModeDisabled
- **Performance Impact**: Zero overhead
- **Use Case**: Production environments where performance is critical
- **Behavior**: All profiling operations are no-ops

### ProfilerModeEnabled
- **Performance Impact**: Minimal overhead (typically < 1%)
- **Use Case**: Development and testing environments
- **Behavior**: Basic profiling with essential metrics

### ProfilerModeDetailed
- **Performance Impact**: Low overhead (typically < 5%)
- **Use Case**: Performance analysis and debugging
- **Behavior**: Comprehensive profiling with detailed metadata

## Performance Issue Detection

The profiler automatically detects common performance issues:

### Slow Operations
- **Detection**: Operations exceeding 100ms average execution time
- **Impact**: High
- **Recommendation**: Optimize algorithm or add caching

### High Iteration Loops
- **Detection**: Loops with more than 1000 iterations
- **Impact**: Medium to High
- **Recommendation**: Consider batch processing or algorithmic improvements

### Slow SQL Queries
- **Detection**: SQL queries taking more than 50ms
- **Impact**: High
- **Recommendation**: Add indexes or optimize query structure

### SQL in Loops (N+1 Problem)
- **Detection**: More than 5 SQL queries executed inside loops
- **Impact**: Critical
- **Recommendation**: Replace with batch operations or JOINs

## Report Formats

### Text Report
Human-readable format suitable for console output and log files.

```
=== Kwil Interpreter Performance Profile Report ===

=== Summary ===
Total Operations: 125
Total Time: 2.543s
Average Time per Operation: 20.34ms

=== Performance Issues ===
[HIGH] SQL in Loop: Detected 15 SQL queries executed inside loops

=== Top Operations by Total Time ===
1. sql.SELECT: 45 calls, 1.234s total (48.5%), 27.4ms avg
2. loop.validation: 8 calls, 678ms total (26.7%), 84.8ms avg
```

### JSON Report
Structured format for programmatic analysis and integration.

```json
{
  "generated_at": "2024-01-15T10:30:00Z",
  "summary": {
    "total_operations": 125,
    "total_time": "2.543s"
  },
  "performance_issues": [
    {
      "type": "sql_in_loop",
      "severity": "high",
      "description": "Detected 15 SQL queries executed inside loops"
    }
  ]
}
```

### CSV Report
Tabular format suitable for spreadsheet analysis.

```csv
Type,Name,Count,Total Time,Average Time,Min Time,Max Time,Percentage
sql,SELECT,45,1.234s,27.4ms,12ms,89ms,48.5%
loop,validation,8,678ms,84.8ms,45ms,156ms,26.7%
```

### HTML Report
Interactive web format with styling and charts.

## Performance Best Practices

### 1. Enable Profiling During Development
```go
config := interpreter.DefaultProfilerConfig()
config.Mode = interpreter.ProfilerModeEnabled
```

### 2. Use Thresholds to Filter Noise
```go
config.MinDurationThreshold = 5 * time.Millisecond
```

### 3. Limit Memory Usage
```go
config.MaxEntries = 5000
```

### 4. Profile Specific Components
```go
config.EnableSQLProfiling = true
config.EnableLoopProfiling = false // Disable if not needed
```

### 5. Regular Performance Testing
```go
// Run profiled tests in CI/CD pipeline
tests := map[string]func(context.Context) error{
    "performance_regression_test": myPerformanceTest,
}

suite, err := runner.RunProfiledTestSuite(ctx, "performance", tests)
```

## Common Performance Issues and Solutions

### Issue: SQL Queries in Loops
```kuneiform
-- BAD: SQL in loop (N+1 problem)
FOR user IN users DO
    SELECT profile FROM user_profiles WHERE user_id = user.id;
END FOR;

-- GOOD: Single query with JOIN
SELECT u.*, p.profile 
FROM users u 
LEFT JOIN user_profiles p ON u.id = p.user_id;
```

### Issue: Excessive Loop Iterations
```kuneiform
-- BAD: Processing each item individually
FOR item IN large_dataset DO
    -- Process single item
END FOR;

-- GOOD: Batch processing
FOR batch IN SELECT * FROM large_dataset LIMIT 100 OFFSET $offset DO
    -- Process batch of items
END FOR;
```

### Issue: Missing Database Indexes
```sql
-- Add indexes for frequently queried columns
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_orders_user_id ON orders(user_id);
```

## Integration Examples

### With Existing Tests
```go
func TestUserCreation(t *testing.T) {
    // Setup profiler
    profiler := interpreter.NewProfiler(interpreter.DefaultProfilerConfig())
    defer profiler.Close()
    
    ctx := interpreter.WithProfiler(context.Background(), profiler)
    
    // Run your test with profiled context
    err := executeUserCreationTest(ctx)
    require.NoError(t, err)
    
    // Analyze results
    summary := profiler.GetSummary()
    assert.Less(t, summary.TotalTime, 100*time.Millisecond, "User creation should complete within 100ms")
    
    // Check for performance issues
    report, _ := profiler.GenerateReport(nil)
    for _, issue := range report.PerformanceIssues {
        if issue.Severity == "critical" {
            t.Errorf("Critical performance issue detected: %s", issue.Description)
        }
    }
}
```

### With Continuous Integration
```yaml
# .github/workflows/performance.yml
name: Performance Testing
on: [push, pull_request]

jobs:
  performance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-go@v2
        with:
          go-version: 1.21
      
      - name: Run Performance Tests
        run: |
          go test -tags=performance ./... -timeout=30m
          
      - name: Upload Performance Reports
        uses: actions/upload-artifact@v2
        with:
          name: performance-reports
          path: ./profiling_reports/
```

## Troubleshooting

### High Memory Usage
If the profiler consumes too much memory, reduce the `MaxEntries` setting:

```go
config.MaxEntries = 1000 // Reduce from default 10000
```

### Missing Profiling Data
Ensure the profiler is properly added to the context:

```go
ctx := interpreter.WithProfiler(context.Background(), profiler)
// Use ctx for all interpreter operations
```

### Performance Impact in Production
Always disable profiling in production:

```go
config.Mode = interpreter.ProfilerModeDisabled
```

## API Reference

### Core Types

- `Profiler`: Main profiler instance
- `ProfilerConfig`: Configuration options
- `ProfilerReport`: Generated performance report
- `ProfiledTestRunner`: Test execution with profiling
- `PerformanceMetrics`: Aggregated performance data

### Key Methods

- `NewProfiler(config)`: Create new profiler
- `WithProfiler(ctx, profiler)`: Add profiler to context
- `StartOperation(type, name, metadata)`: Begin profiling operation
- `EndOperation(id, errorCount)`: End profiling operation
- `GenerateReport(config)`: Create performance report
- `WriteReport(writer, config)`: Output report in specified format

## Contributing

To contribute to the profiler:

1. Add new performance issue detectors in `detectPerformanceIssues()`
2. Implement new report formats in `WriteReport()`
3. Add profiling hooks for new operation types
4. Extend test coverage for edge cases

## License

This profiler is part of the Kwil project and follows the same licensing terms.