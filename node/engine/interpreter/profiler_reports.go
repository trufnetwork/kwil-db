package interpreter

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// ReportFormat represents the format of the profiling report
type ReportFormat string

const (
	ReportFormatText ReportFormat = "text"
	ReportFormatJSON ReportFormat = "json"
	ReportFormatCSV  ReportFormat = "csv"
	ReportFormatHTML ReportFormat = "html"
)

// ProfilerReportConfig holds configuration for report generation
type ProfilerReportConfig struct {
	Format           ReportFormat
	IncludeCallStack bool
	IncludeMetadata  bool
	TopN             int
	MinDuration      time.Duration
	GroupBy          []string // group by: type, name, namespace
}

// DefaultReportConfig returns a default report configuration
func DefaultReportConfig() *ProfilerReportConfig {
	return &ProfilerReportConfig{
		Format:           ReportFormatText,
		IncludeCallStack: false,
		IncludeMetadata:  true,
		TopN:             20,
		MinDuration:      1 * time.Millisecond,
		GroupBy:          []string{"type"},
	}
}

// ProfilerReport represents a complete profiling report
type ProfilerReport struct {
	GeneratedAt     time.Time                `json:"generated_at"`
	Config          *ProfilerReportConfig    `json:"config"`
	Summary         *ProfileSummary          `json:"summary"`
	TopOperations   []OperationReport        `json:"top_operations"`
	CallStack       []CallStackEntry         `json:"call_stack,omitempty"`
	PerformanceIssues []PerformanceIssue     `json:"performance_issues"`
	Recommendations []string                 `json:"recommendations"`
}

// CallStackEntry represents an entry in the call stack
type CallStackEntry struct {
	ID       string                 `json:"id"`
	Type     string                 `json:"type"`
	Name     string                 `json:"name"`
	Depth    int                    `json:"depth"`
	Duration time.Duration          `json:"duration"`
	Children []CallStackEntry       `json:"children,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// PerformanceIssue represents a detected performance issue
type PerformanceIssue struct {
	Type        string        `json:"type"`
	Severity    string        `json:"severity"`
	Operation   string        `json:"operation"`
	Description string        `json:"description"`
	Duration    time.Duration `json:"duration"`
	Count       int           `json:"count"`
}

// GenerateDetailedReport generates a comprehensive profiling report
func (p *Profiler) GenerateDetailedReport(config *ProfilerReportConfig) (*ProfilerReport, error) {
	if !p.IsEnabled() {
		return nil, fmt.Errorf("profiler is not enabled")
	}

	if config == nil {
		config = DefaultReportConfig()
	}

	summary := p.GetSummary()
	if summary == nil {
		return &ProfilerReport{
			GeneratedAt: time.Now(),
			Config:      config,
			Summary:     &ProfileSummary{},
		}, nil
	}

	report := &ProfilerReport{
		GeneratedAt: time.Now(),
		Config:      config,
		Summary:     summary,
		TopOperations: summary.GetTopOperations(config.TopN),
	}

	// Generate call stack if requested
	if config.IncludeCallStack {
		report.CallStack = p.buildCallStack()
	}

	// Detect performance issues
	report.PerformanceIssues = p.detectPerformanceIssues()

	// Generate recommendations
	report.Recommendations = p.generateRecommendations(report)

	return report, nil
}

// buildCallStack builds a hierarchical call stack from the profiling entries
func (p *Profiler) buildCallStack() []CallStackEntry {
	entries := p.GetEntries()
	if len(entries) == 0 {
		return nil
	}

	// Build a map of entries by ID for quick lookup
	entryMap := make(map[string]ProfileEntry)
	for _, entry := range entries {
		entryMap[entry.ID] = entry
	}

	// Build the call stack hierarchy
	var rootEntries []CallStackEntry
	entryToCallStack := make(map[string]*CallStackEntry)

	// First pass: create call stack entries
	for _, entry := range entries {
		callStackEntry := CallStackEntry{
			ID:       entry.ID,
			Type:     entry.Type,
			Name:     entry.Name,
			Depth:    entry.Depth,
			Duration: entry.Duration,
			Metadata: entry.Metadata,
		}
		entryToCallStack[entry.ID] = &callStackEntry
	}

	// Second pass: build hierarchy
	for _, entry := range entries {
		callStackEntry := entryToCallStack[entry.ID]
		
		if entry.ParentID == "" {
			// Root entry
			rootEntries = append(rootEntries, *callStackEntry)
		} else if parent, exists := entryToCallStack[entry.ParentID]; exists {
			// Add as child to parent
			parent.Children = append(parent.Children, *callStackEntry)
		}
	}

	return rootEntries
}

// detectPerformanceIssues analyzes profiling data to detect performance issues
func (p *Profiler) detectPerformanceIssues() []PerformanceIssue {
	var issues []PerformanceIssue
	summary := p.GetSummary()
	entries := p.GetEntries()

	if summary == nil || len(entries) == 0 {
		return issues
	}

	// Define thresholds
	slowOperationThreshold := 100 * time.Millisecond
	highIterationThreshold := int64(1000)
	longSQLQueryThreshold := 50 * time.Millisecond

	// Check for slow operations
	for _, op := range summary.GetTopOperations(10) {
		if op.AvgTime > slowOperationThreshold {
			issues = append(issues, PerformanceIssue{
				Type:        "slow_operation",
				Severity:    getSeverity(op.AvgTime, slowOperationThreshold),
				Operation:   fmt.Sprintf("%s.%s", op.Type, op.Name),
				Description: fmt.Sprintf("Operation has high average execution time: %v", op.AvgTime),
				Duration:    op.AvgTime,
				Count:       op.Count,
			})
		}
	}

	// Check for high iteration loops
	for _, entry := range entries {
		if entry.Type == "loop" && entry.LoopCount > highIterationThreshold {
			issues = append(issues, PerformanceIssue{
				Type:        "high_iteration_loop",
				Severity:    getSeverity(time.Duration(entry.LoopCount), time.Duration(highIterationThreshold)),
				Operation:   entry.Name,
				Description: fmt.Sprintf("Loop has high iteration count: %d iterations", entry.LoopCount),
				Duration:    entry.Duration,
				Count:       int(entry.LoopCount),
			})
		}
	}

	// Check for slow SQL queries
	for _, entry := range entries {
		if entry.Type == "sql" && entry.Duration > longSQLQueryThreshold {
			issues = append(issues, PerformanceIssue{
				Type:        "slow_sql_query",
				Severity:    getSeverity(entry.Duration, longSQLQueryThreshold),
				Operation:   "SQL Query",
				Description: fmt.Sprintf("SQL query execution time is high: %v", entry.Duration),
				Duration:    entry.Duration,
				Count:       1,
			})
		}
	}

	// Check for SQL queries in loops (N+1 problem)
	sqlInLoopCount := 0
	for _, entry := range entries {
		if entry.Type == "sql" && entry.ParentID != "" {
			// Check if parent is a loop
			for _, parentEntry := range entries {
				if parentEntry.ID == entry.ParentID && parentEntry.Type == "loop" {
					sqlInLoopCount++
					break
				}
			}
		}
	}

	if sqlInLoopCount > 5 {
		issues = append(issues, PerformanceIssue{
			Type:        "sql_in_loop",
			Severity:    "high",
			Operation:   "SQL in Loop",
			Description: fmt.Sprintf("Detected %d SQL queries executed inside loops (potential N+1 problem)", sqlInLoopCount),
			Count:       sqlInLoopCount,
		})
	}

	return issues
}

// getSeverity determines the severity of a performance issue
func getSeverity(actual, threshold time.Duration) string {
	ratio := float64(actual) / float64(threshold)
	if ratio > 10 {
		return "critical"
	} else if ratio > 5 {
		return "high"
	} else if ratio > 2 {
		return "medium"
	}
	return "low"
}

// generateRecommendations generates performance recommendations based on the analysis
func (p *Profiler) generateRecommendations(report *ProfilerReport) []string {
	var recommendations []string

	// Analyze performance issues and generate recommendations
	for _, issue := range report.PerformanceIssues {
		switch issue.Type {
		case "slow_operation":
			recommendations = append(recommendations, 
				fmt.Sprintf("Consider optimizing %s operation which has an average execution time of %v", 
					issue.Operation, issue.Duration))
		case "high_iteration_loop":
			recommendations = append(recommendations, 
				fmt.Sprintf("Review loop implementation in %s - %d iterations may be excessive", 
					issue.Operation, issue.Count))
		case "slow_sql_query":
			recommendations = append(recommendations, 
				"Consider adding database indexes or optimizing SQL query structure for slow queries")
		case "sql_in_loop":
			recommendations = append(recommendations, 
				"Replace SQL queries inside loops with batch operations or single queries with JOINs to avoid N+1 problems")
		}
	}

	// General recommendations based on operation patterns
	if len(report.TopOperations) > 0 {
		topOp := report.TopOperations[0]
		if topOp.Type == "sql" {
			recommendations = append(recommendations, 
				"SQL operations dominate execution time - consider query optimization and indexing")
		} else if topOp.Type == "loop" {
			recommendations = append(recommendations, 
				"Loop operations dominate execution time - consider algorithmic improvements")
		}
	}

	return recommendations
}

// WriteReport writes the profiling report to the specified writer in the configured format
func (p *Profiler) WriteReport(w io.Writer, config *ProfilerReportConfig) error {
	report, err := p.GenerateDetailedReport(config)
	if err != nil {
		return err
	}

	switch config.Format {
	case ReportFormatText:
		return p.writeTextReport(w, report)
	case ReportFormatJSON:
		return p.writeJSONReport(w, report)
	case ReportFormatCSV:
		return p.writeCSVReport(w, report)
	case ReportFormatHTML:
		return p.writeHTMLReport(w, report)
	default:
		return fmt.Errorf("unsupported report format: %s", config.Format)
	}
}

// writeTextReport writes a human-readable text report
func (p *Profiler) writeTextReport(w io.Writer, report *ProfilerReport) error {
	var sb strings.Builder
	sb.WriteString("=== Kwil Interpreter Performance Profile Report ===\n\n")
	sb.WriteString(fmt.Sprintf("Generated at: %s\n\n", report.GeneratedAt.Format(time.RFC3339)))

	// Overall summary
	if report.Summary != nil {
		sb.WriteString("=== Summary ===\n")
		sb.WriteString(fmt.Sprintf("Total Operations: %d\n", report.Summary.TotalOperations))
		sb.WriteString(fmt.Sprintf("Total Time: %v\n", report.Summary.TotalTime))
		if report.Summary.TotalOperations > 0 {
			avgTime := report.Summary.TotalTime / time.Duration(report.Summary.TotalOperations)
			sb.WriteString(fmt.Sprintf("Average Time per Operation: %v\n\n", avgTime))
		}
	}

	// Performance issues
	if len(report.PerformanceIssues) > 0 {
		sb.WriteString("=== Performance Issues ===\n")
		for _, issue := range report.PerformanceIssues {
			sb.WriteString(fmt.Sprintf("[%s] %s: %s\n", 
				strings.ToUpper(issue.Severity), issue.Operation, issue.Description))
		}
		sb.WriteString("\n")
	}

	// Top operations
	if len(report.TopOperations) > 0 {
		sb.WriteString("=== Top Operations by Total Time ===\n")
		for i, op := range report.TopOperations {
			pct := float64(op.TotalTime) / float64(report.Summary.TotalTime) * 100
			sb.WriteString(fmt.Sprintf("%d. %s.%s: %d calls, %v total (%.1f%%), %v avg\n",
				i+1, op.Type, op.Name, op.Count, op.TotalTime, pct, op.AvgTime))
		}
		sb.WriteString("\n")
	}

	// Recommendations
	if len(report.Recommendations) > 0 {
		sb.WriteString("=== Recommendations ===\n")
		for i, rec := range report.Recommendations {
			sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, rec))
		}
	}

	_, err := w.Write([]byte(sb.String()))
	return err
}

// writeJSONReport writes the report in JSON format
func (p *Profiler) writeJSONReport(w io.Writer, report *ProfilerReport) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// writeCSVReport writes the report in CSV format
func (p *Profiler) writeCSVReport(w io.Writer, report *ProfilerReport) error {
	csvWriter := csv.NewWriter(w)
	defer csvWriter.Flush()

	// Write header
	header := []string{
		"Type", "Name", "Count", "Total Time", "Average Time", "Min Time", "Max Time", "Percentage",
	}
	if err := csvWriter.Write(header); err != nil {
		return err
	}

	// Write data
	for _, op := range report.TopOperations {
		pct := float64(op.TotalTime) / float64(report.Summary.TotalTime) * 100
		record := []string{
			op.Type,
			op.Name,
			fmt.Sprintf("%d", op.Count),
			op.TotalTime.String(),
			op.AvgTime.String(),
			op.MinTime.String(),
			op.MaxTime.String(),
			fmt.Sprintf("%.2f%%", pct),
		}
		if err := csvWriter.Write(record); err != nil {
			return err
		}
	}

	return nil
}

// writeHTMLReport writes the report in HTML format
func (p *Profiler) writeHTMLReport(w io.Writer, report *ProfilerReport) error {
	html := `<!DOCTYPE html>
<html>
<head>
    <title>Kwil Interpreter Performance Profile</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .summary { background-color: #f9f9f9; padding: 15px; border-radius: 5px; }
        .issue-critical { color: #d32f2f; }
        .issue-high { color: #f57c00; }
        .issue-medium { color: #fbc02d; }
        .issue-low { color: #388e3c; }
    </style>
</head>
<body>
    <h1>Kwil Interpreter Performance Profile</h1>
    <p><strong>Generated at:</strong> %s</p>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total Operations:</strong> %d</p>
        <p><strong>Total Time:</strong> %v</p>
        <p><strong>Average Time per Operation:</strong> %v</p>
    </div>`

	avgTime := time.Duration(0)
	if report.Summary != nil && report.Summary.TotalOperations > 0 {
		avgTime = report.Summary.TotalTime / time.Duration(report.Summary.TotalOperations)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(html, 
		report.GeneratedAt.Format(time.RFC3339),
		report.Summary.TotalOperations,
		report.Summary.TotalTime,
		avgTime,
	))

	// Performance issues
	if len(report.PerformanceIssues) > 0 {
		sb.WriteString(`
    <h2>Performance Issues</h2>
    <table>
        <tr><th>Severity</th><th>Operation</th><th>Description</th></tr>`)
		
		for _, issue := range report.PerformanceIssues {
			sb.WriteString(fmt.Sprintf(`
        <tr>
            <td class="issue-%s">%s</td>
            <td>%s</td>
            <td>%s</td>
        </tr>`, issue.Severity, strings.ToUpper(issue.Severity), issue.Operation, issue.Description))
		}
		sb.WriteString("</table>")
	}

	// Top operations
	if len(report.TopOperations) > 0 {
		sb.WriteString(`
    <h2>Top Operations</h2>
    <table>
        <tr><th>Rank</th><th>Type</th><th>Name</th><th>Count</th><th>Total Time</th><th>Avg Time</th><th>%</th></tr>`)
		
		for i, op := range report.TopOperations {
			pct := float64(op.TotalTime) / float64(report.Summary.TotalTime) * 100
			sb.WriteString(fmt.Sprintf(`
        <tr>
            <td>%d</td>
            <td>%s</td>
            <td>%s</td>
            <td>%d</td>
            <td>%v</td>
            <td>%v</td>
            <td>%.1f%%</td>
        </tr>`, i+1, op.Type, op.Name, op.Count, op.TotalTime, op.AvgTime, pct))
		}
		sb.WriteString("</table>")
	}

	// Recommendations
	if len(report.Recommendations) > 0 {
		sb.WriteString(`
    <h2>Recommendations</h2>
    <ol>`)
		for _, rec := range report.Recommendations {
			sb.WriteString(fmt.Sprintf("<li>%s</li>", rec))
		}
		sb.WriteString("</ol>")
	}

	sb.WriteString(`
</body>
</html>`)

	_, err := w.Write([]byte(sb.String()))
	return err
}