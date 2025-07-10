package interpreter

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// ProfilerMode represents different profiling modes
type ProfilerMode int

const (
	ProfilerModeDisabled ProfilerMode = iota
	ProfilerModeEnabled
	ProfilerModeDetailed
)

// ProfilerConfig holds configuration for the profiler
type ProfilerConfig struct {
	Mode               ProfilerMode
	EnableSQLProfiling bool
	EnableLoopProfiling bool
	EnableActionProfiling bool
	EnableFunctionProfiling bool
	MinDurationThreshold time.Duration
	MaxEntries          int
}

// DefaultProfilerConfig returns a default profiler configuration
func DefaultProfilerConfig() *ProfilerConfig {
	return &ProfilerConfig{
		Mode:               ProfilerModeDisabled,
		EnableSQLProfiling: true,
		EnableLoopProfiling: true,
		EnableActionProfiling: true,
		EnableFunctionProfiling: true,
		MinDurationThreshold: 1 * time.Millisecond,
		MaxEntries:          10000,
	}
}

// ProfileEntry represents a single profiling entry
type ProfileEntry struct {
	ID          string
	Type        string
	Name        string
	StartTime   time.Time
	EndTime     time.Time
	Duration    time.Duration
	ParentID    string
	Depth       int
	Metadata    map[string]interface{}
	SQLQuery    string
	LoopCount   int64
	ReturnCount int64
	ErrorCount  int64
}

// Profiler manages performance profiling for the interpreter
type Profiler struct {
	config  *ProfilerConfig
	entries []ProfileEntry
	mu      sync.RWMutex
	
	// Stack for tracking nested operations
	stack   []string
	stackMu sync.RWMutex
	
	// Counters for generating unique IDs
	counter int64
	
	// Context for cancellation
	ctx    context.Context
	cancel context.CancelFunc
}

// NewProfiler creates a new profiler instance
func NewProfiler(config *ProfilerConfig) *Profiler {
	if config == nil {
		config = DefaultProfilerConfig()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	return &Profiler{
		config:  config,
		entries: make([]ProfileEntry, 0, config.MaxEntries),
		stack:   make([]string, 0),
		ctx:     ctx,
		cancel:  cancel,
	}
}

// IsEnabled returns true if profiling is enabled
func (p *Profiler) IsEnabled() bool {
	if p == nil || p.config == nil {
		return false
	}
	return p.config.Mode != ProfilerModeDisabled
}

// StartOperation begins profiling an operation
func (p *Profiler) StartOperation(operationType, name string, metadata map[string]interface{}) string {
	if !p.IsEnabled() {
		return ""
	}
	
	p.mu.Lock()
	defer p.mu.Unlock()
	
	// Check if we've reached the max entries limit
	if len(p.entries) >= p.config.MaxEntries {
		return ""
	}
	
	// Generate unique ID
	p.counter++
	id := fmt.Sprintf("%s_%d", operationType, p.counter)
	
	// Get parent ID
	p.stackMu.RLock()
	var parentID string
	if len(p.stack) > 0 {
		parentID = p.stack[len(p.stack)-1]
	}
	depth := len(p.stack)
	p.stackMu.RUnlock()
	
	// Create entry
	entry := ProfileEntry{
		ID:        id,
		Type:      operationType,
		Name:      name,
		StartTime: time.Now(),
		ParentID:  parentID,
		Depth:     depth,
		Metadata:  metadata,
	}
	
	p.entries = append(p.entries, entry)
	
	// Add to stack
	p.stackMu.Lock()
	p.stack = append(p.stack, id)
	p.stackMu.Unlock()
	
	return id
}

// EndOperation ends profiling an operation
func (p *Profiler) EndOperation(id string, errorCount int64) {
	if !p.IsEnabled() || id == "" {
		return
	}
	
	endTime := time.Now()
	
	p.mu.Lock()
	defer p.mu.Unlock()
	
	// Find the entry
	for i := len(p.entries) - 1; i >= 0; i-- {
		if p.entries[i].ID == id {
			p.entries[i].EndTime = endTime
			p.entries[i].Duration = endTime.Sub(p.entries[i].StartTime)
			p.entries[i].ErrorCount = errorCount
			break
		}
	}
	
	// Remove from stack
	p.stackMu.Lock()
	for i := len(p.stack) - 1; i >= 0; i-- {
		if p.stack[i] == id {
			p.stack = append(p.stack[:i], p.stack[i+1:]...)
			break
		}
	}
	p.stackMu.Unlock()
}

// RecordSQLQuery records a SQL query execution
func (p *Profiler) RecordSQLQuery(id, query string, duration time.Duration) {
	if !p.IsEnabled() || !p.config.EnableSQLProfiling || id == "" {
		return
	}
	
	p.mu.Lock()
	defer p.mu.Unlock()
	
	// Find the entry and update it
	for i := len(p.entries) - 1; i >= 0; i-- {
		if p.entries[i].ID == id {
			p.entries[i].SQLQuery = query
			if p.entries[i].Metadata == nil {
				p.entries[i].Metadata = make(map[string]interface{})
			}
			p.entries[i].Metadata["sql_duration"] = duration
			break
		}
	}
}

// RecordLoopIteration records a loop iteration
func (p *Profiler) RecordLoopIteration(id string, iterationCount int64) {
	if !p.IsEnabled() || !p.config.EnableLoopProfiling || id == "" {
		return
	}
	
	p.mu.Lock()
	defer p.mu.Unlock()
	
	// Find the entry and update it
	for i := len(p.entries) - 1; i >= 0; i-- {
		if p.entries[i].ID == id {
			p.entries[i].LoopCount = iterationCount
			break
		}
	}
}

// RecordReturnCount records the number of return statements executed
func (p *Profiler) RecordReturnCount(id string, returnCount int64) {
	if !p.IsEnabled() || id == "" {
		return
	}
	
	p.mu.Lock()
	defer p.mu.Unlock()
	
	// Find the entry and update it
	for i := len(p.entries) - 1; i >= 0; i-- {
		if p.entries[i].ID == id {
			p.entries[i].ReturnCount = returnCount
			break
		}
	}
}

// GetEntries returns all profiling entries
func (p *Profiler) GetEntries() []ProfileEntry {
	if !p.IsEnabled() {
		return nil
	}
	
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	// Filter by minimum duration threshold
	filtered := make([]ProfileEntry, 0, len(p.entries))
	for _, entry := range p.entries {
		if entry.Duration >= p.config.MinDurationThreshold {
			filtered = append(filtered, entry)
		}
	}
	
	return filtered
}

// GetSummary returns a summary of profiling data
func (p *Profiler) GetSummary() *ProfileSummary {
	if !p.IsEnabled() {
		return nil
	}
	
	entries := p.GetEntries()
	if len(entries) == 0 {
		return &ProfileSummary{}
	}
	
	summary := &ProfileSummary{
		TotalOperations: len(entries),
		OperationTypes:  make(map[string]*OperationTypeSummary),
	}
	
	var totalDuration time.Duration
	for _, entry := range entries {
		totalDuration += entry.Duration
		
		// Update operation type summary
		if _, exists := summary.OperationTypes[entry.Type]; !exists {
			summary.OperationTypes[entry.Type] = &OperationTypeSummary{
				Count:      0,
				TotalTime:  0,
				MinTime:    entry.Duration,
				MaxTime:    entry.Duration,
				Operations: make(map[string]*OperationSummary),
			}
		}
		
		typeSum := summary.OperationTypes[entry.Type]
		typeSum.Count++
		typeSum.TotalTime += entry.Duration
		if entry.Duration < typeSum.MinTime {
			typeSum.MinTime = entry.Duration
		}
		if entry.Duration > typeSum.MaxTime {
			typeSum.MaxTime = entry.Duration
		}
		
		// Update specific operation summary
		if _, exists := typeSum.Operations[entry.Name]; !exists {
			typeSum.Operations[entry.Name] = &OperationSummary{
				Count:     0,
				TotalTime: 0,
				MinTime:   entry.Duration,
				MaxTime:   entry.Duration,
			}
		}
		
		opSum := typeSum.Operations[entry.Name]
		opSum.Count++
		opSum.TotalTime += entry.Duration
		if entry.Duration < opSum.MinTime {
			opSum.MinTime = entry.Duration
		}
		if entry.Duration > opSum.MaxTime {
			opSum.MaxTime = entry.Duration
		}
	}
	
	summary.TotalTime = totalDuration
	return summary
}

// Clear clears all profiling data
func (p *Profiler) Clear() {
	if !p.IsEnabled() {
		return
	}
	
	p.mu.Lock()
	defer p.mu.Unlock()
	
	p.entries = p.entries[:0]
	p.counter = 0
	
	p.stackMu.Lock()
	p.stack = p.stack[:0]
	p.stackMu.Unlock()
}

// Close closes the profiler
func (p *Profiler) Close() {
	if p.cancel != nil {
		p.cancel()
	}
}

// ProfileSummary contains a summary of profiling data
type ProfileSummary struct {
	TotalOperations int
	TotalTime       time.Duration
	OperationTypes  map[string]*OperationTypeSummary
}

// OperationTypeSummary contains summary data for a specific operation type
type OperationTypeSummary struct {
	Count      int
	TotalTime  time.Duration
	MinTime    time.Duration
	MaxTime    time.Duration
	Operations map[string]*OperationSummary
}

// OperationSummary contains summary data for a specific operation
type OperationSummary struct {
	Count     int
	TotalTime time.Duration
	MinTime   time.Duration
	MaxTime   time.Duration
}

// GetTopOperations returns the top N operations by total time
func (s *ProfileSummary) GetTopOperations(n int) []OperationReport {
	var reports []OperationReport
	
	for typeName, typeSum := range s.OperationTypes {
		for opName, opSum := range typeSum.Operations {
			reports = append(reports, OperationReport{
				Type:      typeName,
				Name:      opName,
				Count:     opSum.Count,
				TotalTime: opSum.TotalTime,
				AvgTime:   opSum.TotalTime / time.Duration(opSum.Count),
				MinTime:   opSum.MinTime,
				MaxTime:   opSum.MaxTime,
			})
		}
	}
	
	// Sort by total time descending
	sort.Slice(reports, func(i, j int) bool {
		return reports[i].TotalTime > reports[j].TotalTime
	})
	
	if n > 0 && n < len(reports) {
		reports = reports[:n]
	}
	
	return reports
}

// OperationReport represents a single operation in the profiling report
type OperationReport struct {
	Type      string
	Name      string
	Count     int
	TotalTime time.Duration
	AvgTime   time.Duration
	MinTime   time.Duration
	MaxTime   time.Duration
}

// GenerateReport generates a simple text profiling report
func (p *Profiler) GenerateReport() string {
	if !p.IsEnabled() {
		return "Profiling is disabled"
	}
	
	summary := p.GetSummary()
	if summary == nil || summary.TotalOperations == 0 {
		return "No profiling data available"
	}
	
	var sb strings.Builder
	sb.WriteString("=== Kwil Interpreter Performance Profile ===\n\n")
	
	// Overall summary
	sb.WriteString(fmt.Sprintf("Total Operations: %d\n", summary.TotalOperations))
	sb.WriteString(fmt.Sprintf("Total Time: %v\n", summary.TotalTime))
	sb.WriteString(fmt.Sprintf("Average Time per Operation: %v\n\n", summary.TotalTime/time.Duration(summary.TotalOperations)))
	
	// Operation type breakdown
	sb.WriteString("=== Operation Type Breakdown ===\n")
	for typeName, typeSum := range summary.OperationTypes {
		avgTime := typeSum.TotalTime / time.Duration(typeSum.Count)
		pct := float64(typeSum.TotalTime) / float64(summary.TotalTime) * 100
		sb.WriteString(fmt.Sprintf("%s: %d ops, %v total (%.1f%%), %v avg, %v min, %v max\n",
			typeName, typeSum.Count, typeSum.TotalTime, pct, avgTime, typeSum.MinTime, typeSum.MaxTime))
	}
	sb.WriteString("\n")
	
	// Top operations
	topOps := summary.GetTopOperations(10)
	if len(topOps) > 0 {
		sb.WriteString("=== Top Operations by Total Time ===\n")
		for i, op := range topOps {
			pct := float64(op.TotalTime) / float64(summary.TotalTime) * 100
			sb.WriteString(fmt.Sprintf("%d. %s.%s: %d calls, %v total (%.1f%%), %v avg\n",
				i+1, op.Type, op.Name, op.Count, op.TotalTime, pct, op.AvgTime))
		}
	}
	
	return sb.String()
}

// profilerCtxKey is used as a key for storing profiler in context
type profilerCtxKey struct{}

// WithProfiler adds a profiler to the context
func WithProfiler(ctx context.Context, profiler *Profiler) context.Context {
	return context.WithValue(ctx, profilerCtxKey{}, profiler)
}

// ProfilerFromContext retrieves a profiler from the context
func ProfilerFromContext(ctx context.Context) *Profiler {
	if profiler, ok := ctx.Value(profilerCtxKey{}).(*Profiler); ok {
		return profiler
	}
	return nil
}