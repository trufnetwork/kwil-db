package interpreter

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/trufnetwork/kwil-db/common"
)

// ProfiledTestResult contains the result of a profiled test execution
type ProfiledTestResult struct {
	TestName        string              `json:"test_name"`
	ExecutionTime   time.Duration       `json:"execution_time"`
	Success         bool                `json:"success"`
	Error           string              `json:"error,omitempty"`
	ProfileReport   *ProfilerReport     `json:"profile_report"`
	PerformanceMetrics *PerformanceMetrics `json:"performance_metrics"`
}

// PerformanceMetrics contains aggregated performance metrics
type PerformanceMetrics struct {
	TotalSQLQueries     int64         `json:"total_sql_queries"`
	TotalLoopIterations int64         `json:"total_loop_iterations"`
	TotalActionCalls    int64         `json:"total_action_calls"`
	TotalFunctionCalls  int64         `json:"total_function_calls"`
	SQLExecutionTime    time.Duration `json:"sql_execution_time"`
	LoopExecutionTime   time.Duration `json:"loop_execution_time"`
	ActionExecutionTime time.Duration `json:"action_execution_time"`
	FunctionExecutionTime time.Duration `json:"function_execution_time"`
}

// ProfiledTestRunner provides profiling capabilities for test execution
type ProfiledTestRunner struct {
	profilerConfig *ProfilerConfig
	reportConfig   *ProfilerReportConfig
	outputDir      string
}

// NewProfiledTestRunner creates a new profiled test runner
func NewProfiledTestRunner(profilerConfig *ProfilerConfig, reportConfig *ProfilerReportConfig, outputDir string) *ProfiledTestRunner {
	if profilerConfig == nil {
		profilerConfig = DefaultProfilerConfig()
		profilerConfig.Mode = ProfilerModeEnabled
	}
	
	if reportConfig == nil {
		reportConfig = DefaultReportConfig()
	}
	
	return &ProfiledTestRunner{
		profilerConfig: profilerConfig,
		reportConfig:   reportConfig,
		outputDir:      outputDir,
	}
}

// RunProfiledTest executes a test with profiling enabled
func (ptr *ProfiledTestRunner) RunProfiledTest(
	ctx context.Context,
	testName string,
	testFunc func(context.Context) error,
) (*ProfiledTestResult, error) {
	// Create profiler
	profiler := NewProfiler(ptr.profilerConfig)
	defer profiler.Close()
	
	// Add profiler to context
	profiledCtx := WithProfiler(ctx, profiler)
	
	// Execute the test
	startTime := time.Now()
	testErr := testFunc(profiledCtx)
	executionTime := time.Since(startTime)
	
	// Generate profiling report
	report, err := profiler.GenerateDetailedReport(ptr.reportConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to generate profiling report: %w", err)
	}
	
	// Calculate performance metrics
	metrics := ptr.calculatePerformanceMetrics(profiler)
	
	result := &ProfiledTestResult{
		TestName:           testName,
		ExecutionTime:      executionTime,
		Success:            testErr == nil,
		ProfileReport:      report,
		PerformanceMetrics: metrics,
	}
	
	if testErr != nil {
		result.Error = testErr.Error()
	}
	
	// Save reports if output directory is specified
	if ptr.outputDir != "" {
		if err := ptr.saveReports(testName, result); err != nil {
			return result, fmt.Errorf("failed to save reports: %w", err)
		}
	}
	
	return result, nil
}

// calculatePerformanceMetrics calculates aggregated performance metrics
func (ptr *ProfiledTestRunner) calculatePerformanceMetrics(profiler *Profiler) *PerformanceMetrics {
	entries := profiler.GetEntries()
	metrics := &PerformanceMetrics{}
	
	for _, entry := range entries {
		switch entry.Type {
		case "sql":
			metrics.TotalSQLQueries++
			metrics.SQLExecutionTime += entry.Duration
		case "loop":
			metrics.TotalLoopIterations += entry.LoopCount
			metrics.LoopExecutionTime += entry.Duration
		case "action":
			metrics.TotalActionCalls++
			metrics.ActionExecutionTime += entry.Duration
		case "function":
			metrics.TotalFunctionCalls++
			metrics.FunctionExecutionTime += entry.Duration
		}
	}
	
	return metrics
}

// saveReports saves profiling reports to the output directory
func (ptr *ProfiledTestRunner) saveReports(testName string, result *ProfiledTestResult) error {
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(ptr.outputDir, 0755); err != nil {
		return err
	}
	
	// Sanitize test name for file names
	sanitizedName := strings.ReplaceAll(testName, "/", "_")
	sanitizedName = strings.ReplaceAll(sanitizedName, " ", "_")
	
	// Save text report
	textFile := filepath.Join(ptr.outputDir, fmt.Sprintf("%s_profile.txt", sanitizedName))
	if err := ptr.saveTextReport(textFile, result.ProfileReport); err != nil {
		return err
	}
	
	// Save JSON report
	jsonFile := filepath.Join(ptr.outputDir, fmt.Sprintf("%s_profile.json", sanitizedName))
	if err := ptr.saveJSONReport(jsonFile, result.ProfileReport); err != nil {
		return err
	}
	
	// Save CSV report
	csvFile := filepath.Join(ptr.outputDir, fmt.Sprintf("%s_profile.csv", sanitizedName))
	if err := ptr.saveCSVReport(csvFile, result.ProfileReport); err != nil {
		return err
	}
	
	// Save HTML report
	htmlFile := filepath.Join(ptr.outputDir, fmt.Sprintf("%s_profile.html", sanitizedName))
	if err := ptr.saveHTMLReport(htmlFile, result.ProfileReport); err != nil {
		return err
	}
	
	return nil
}

// saveTextReport saves a text report to file
func (ptr *ProfiledTestRunner) saveTextReport(filename string, report *ProfilerReport) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	profiler := NewProfiler(ptr.profilerConfig)
	config := *ptr.reportConfig
	config.Format = ReportFormatText
	return profiler.writeTextReport(file, report)
}

// saveJSONReport saves a JSON report to file
func (ptr *ProfiledTestRunner) saveJSONReport(filename string, report *ProfilerReport) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	profiler := NewProfiler(ptr.profilerConfig)
	config := *ptr.reportConfig
	config.Format = ReportFormatJSON
	return profiler.writeJSONReport(file, report)
}

// saveCSVReport saves a CSV report to file
func (ptr *ProfiledTestRunner) saveCSVReport(filename string, report *ProfilerReport) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	profiler := NewProfiler(ptr.profilerConfig)
	config := *ptr.reportConfig
	config.Format = ReportFormatCSV
	return profiler.writeCSVReport(file, report)
}

// saveHTMLReport saves an HTML report to file
func (ptr *ProfiledTestRunner) saveHTMLReport(filename string, report *ProfilerReport) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	profiler := NewProfiler(ptr.profilerConfig)
	config := *ptr.reportConfig
	config.Format = ReportFormatHTML
	return profiler.writeHTMLReport(file, report)
}

// TestSuite represents a collection of profiled tests
type TestSuite struct {
	Name    string                `json:"name"`
	Tests   []ProfiledTestResult  `json:"tests"`
	Summary *TestSuiteSummary     `json:"summary"`
}

// TestSuiteSummary contains aggregated metrics for a test suite
type TestSuiteSummary struct {
	TotalTests      int           `json:"total_tests"`
	PassedTests     int           `json:"passed_tests"`
	FailedTests     int           `json:"failed_tests"`
	TotalTime       time.Duration `json:"total_time"`
	AverageTime     time.Duration `json:"average_time"`
	SlowestTest     string        `json:"slowest_test"`
	SlowestTime     time.Duration `json:"slowest_time"`
	PerformanceIssues int         `json:"performance_issues"`
}

// RunProfiledTestSuite executes a suite of profiled tests
func (ptr *ProfiledTestRunner) RunProfiledTestSuite(
	ctx context.Context,
	suiteName string,
	tests map[string]func(context.Context) error,
) (*TestSuite, error) {
	suite := &TestSuite{
		Name:  suiteName,
		Tests: make([]ProfiledTestResult, 0, len(tests)),
	}
	
	for testName, testFunc := range tests {
		result, err := ptr.RunProfiledTest(ctx, testName, testFunc)
		if err != nil {
			return nil, fmt.Errorf("failed to run test %s: %w", testName, err)
		}
		suite.Tests = append(suite.Tests, *result)
	}
	
	// Calculate suite summary
	suite.Summary = ptr.calculateTestSuiteSummary(suite.Tests)
	
	// Save suite report
	if ptr.outputDir != "" {
		if err := ptr.saveTestSuiteReport(suiteName, suite); err != nil {
			return suite, fmt.Errorf("failed to save test suite report: %w", err)
		}
	}
	
	return suite, nil
}

// calculateTestSuiteSummary calculates summary metrics for a test suite
func (ptr *ProfiledTestRunner) calculateTestSuiteSummary(tests []ProfiledTestResult) *TestSuiteSummary {
	summary := &TestSuiteSummary{
		TotalTests: len(tests),
	}
	
	var totalTime time.Duration
	var slowestTime time.Duration
	var slowestTest string
	var totalIssues int
	
	for _, test := range tests {
		if test.Success {
			summary.PassedTests++
		} else {
			summary.FailedTests++
		}
		
		totalTime += test.ExecutionTime
		
		if test.ExecutionTime > slowestTime {
			slowestTime = test.ExecutionTime
			slowestTest = test.TestName
		}
		
		if test.ProfileReport != nil {
			totalIssues += len(test.ProfileReport.PerformanceIssues)
		}
	}
	
	summary.TotalTime = totalTime
	if summary.TotalTests > 0 {
		summary.AverageTime = totalTime / time.Duration(summary.TotalTests)
	}
	summary.SlowestTest = slowestTest
	summary.SlowestTime = slowestTime
	summary.PerformanceIssues = totalIssues
	
	return summary
}

// saveTestSuiteReport saves a test suite report
func (ptr *ProfiledTestRunner) saveTestSuiteReport(suiteName string, suite *TestSuite) error {
	sanitizedName := strings.ReplaceAll(suiteName, "/", "_")
	sanitizedName = strings.ReplaceAll(sanitizedName, " ", "_")
	
	filename := filepath.Join(ptr.outputDir, fmt.Sprintf("%s_suite_report.json", sanitizedName))
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	profiler := NewProfiler(ptr.profilerConfig)
	return profiler.writeJSONReport(file, &ProfilerReport{
		GeneratedAt: time.Now(),
		Config:      ptr.reportConfig,
		Summary: &ProfileSummary{
			TotalOperations: suite.Summary.TotalTests,
			TotalTime:       suite.Summary.TotalTime,
		},
	})
}

// ProfiledEngineContext extends common.EngineContext with profiling support
type ProfiledEngineContext struct {
	*common.EngineContext
	Profiler *Profiler
}

// NewProfiledEngineContext creates a new profiled engine context
func NewProfiledEngineContext(base *common.EngineContext, profiler *Profiler) *ProfiledEngineContext {
	// Add profiler to the context
	ctx := WithProfiler(base.TxContext.Ctx, profiler)
	
	// Create a new engine context with the profiled context
	profiledBase := &common.EngineContext{
		TxContext: &common.TxContext{
			Ctx:           ctx,
			BlockContext:  base.TxContext.BlockContext,
			TxID:          base.TxContext.TxID,
			Caller:        base.TxContext.Caller,
			Signer:        base.TxContext.Signer,
			Authenticator: base.TxContext.Authenticator,
		},
		OverrideAuthz: base.OverrideAuthz,
		InvalidTxCtx:  base.InvalidTxCtx,
	}
	
	return &ProfiledEngineContext{
		EngineContext: profiledBase,
		Profiler:      profiler,
	}
}

// GetProfileReport returns the current profiling report
func (pec *ProfiledEngineContext) GetProfileReport(config *ProfilerReportConfig) (*ProfilerReport, error) {
	if pec.Profiler == nil {
		return nil, fmt.Errorf("profiler not available")
	}
	return pec.Profiler.GenerateDetailedReport(config)
}

// WriteProfileReport writes the profiling report to the specified writer
func (pec *ProfiledEngineContext) WriteProfileReport(w io.Writer, config *ProfilerReportConfig) error {
	if pec.Profiler == nil {
		return fmt.Errorf("profiler not available")
	}
	return pec.Profiler.WriteReport(w, config)
}

// GetPerformanceMetrics returns the current performance metrics
func (pec *ProfiledEngineContext) GetPerformanceMetrics() *PerformanceMetrics {
	if pec.Profiler == nil {
		return nil
	}
	
	runner := &ProfiledTestRunner{profilerConfig: pec.Profiler.config}
	return runner.calculatePerformanceMetrics(pec.Profiler)
}