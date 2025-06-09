package interpreter

import (
	"encoding/json"
	"fmt"
	"log"
	"time"
)

// ExampleUsage demonstrates how to use the profiling feature
func ExampleUsage() {
	// This is a PSEUDO CODE example showing how to use the profiling feature
	// The actual integration would depend on where the interpreter is called from

	// 1. Create the ROOT execution context with profiling enabled
	rootCtx := &executionContext{
		// ... initialize all other fields as normal ...
		EnableProfiling: true, // Enable profiling
	}

	// 2. Initialize the profiling records slice
	records := []ProfileRecord{}
	rootCtx.profileRecords = &records // MUST initialize the pointer

	// 3. Run the execution (this would be the actual interpreter execution)
	// err := executable.Func(rootCtx, args, fn)
	// ... actual execution happens here ...

	// 4. Retrieve and display the profiling results
	profileOutput := rootCtx.GetProfileRecords()

	if len(profileOutput) > 0 {
		log.Println("------ PROFILE RESULTS ------")

		// Calculate total time from first start to last end
		totalDuration := time.Duration(0)
		if len(profileOutput) > 0 {
			firstStart := profileOutput[0].StartTime
			lastRecord := profileOutput[len(profileOutput)-1]
			lastEnd := lastRecord.StartTime.Add(lastRecord.Duration)
			totalDuration = lastEnd.Sub(firstStart)
		}

		// Print each profiling record
		for i, rec := range profileOutput {
			log.Printf("%03d: %s\n", i, rec.String())
		}

		log.Printf("------ TOTAL OBSERVED: %s ------\n", totalDuration)

		// Example: Export as JSON
		jsonData, err := json.MarshalIndent(profileOutput, "", "  ")
		if err == nil {
			fmt.Println("JSON Output:")
			fmt.Println(string(jsonData))
		}

		// Example: Find slowest operations
		var slowest ProfileRecord
		for _, rec := range profileOutput {
			if rec.Duration > slowest.Duration {
				slowest = rec
			}
		}
		log.Printf("Slowest operation: %s took %s\n", slowest.Identifier, slowest.DurationStr)
	}
}

// ProfiledExecutionExample shows how to wrap an execution with profiling
func ProfiledExecutionExample(enableProfiling bool) ([]ProfileRecord, error) {
	// Create execution context
	ctx := &executionContext{
		// ... other fields ...
		EnableProfiling: enableProfiling,
	}

	// Initialize profiling if enabled
	if enableProfiling {
		records := []ProfileRecord{}
		ctx.profileRecords = &records
	}

	// Execute your interpreter logic here
	// err := someInterpreterExecution(ctx)

	// Return profiling results
	if enableProfiling {
		return ctx.GetProfileRecords(), nil
	}
	return nil, nil
}
