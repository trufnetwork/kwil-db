package interpreter

import (
	"regexp"
	"strings"
)

// QueryType represents the type of SQL query being executed
type QueryType int

const (
	QueryTypeUnknown QueryType = iota
	QueryTypeSelect
	QueryTypeInsert
	QueryTypeUpdate
	QueryTypeDelete
	QueryTypeWith
)

// QueryExecutionState tracks the current query execution context
type QueryExecutionState struct {
	active      bool
	queryType   QueryType
	allowNested bool
	sql         string
}

// analyzeQueryType determines the type of SQL query
func analyzeQueryType(sql string) QueryType {
	sql = strings.TrimSpace(strings.ToUpper(sql))

	if strings.HasPrefix(sql, "WITH") {
		return QueryTypeWith
	} else if strings.HasPrefix(sql, "SELECT") {
		return QueryTypeSelect
	} else if strings.HasPrefix(sql, "INSERT") {
		return QueryTypeInsert
	} else if strings.HasPrefix(sql, "UPDATE") {
		return QueryTypeUpdate
	} else if strings.HasPrefix(sql, "DELETE") {
		return QueryTypeDelete
	}

	return QueryTypeUnknown
}

// containsWithRecursiveDML checks if the query contains WITH RECURSIVE in a DML context
func containsWithRecursiveDML(sql string) bool {
	sql = strings.ToUpper(sql)

	// Check for WITH RECURSIVE pattern
	hasWithRecursive := strings.Contains(sql, "WITH RECURSIVE")
	if !hasWithRecursive {
		return false
	}

	// Check if it's in a DML context (INSERT, UPDATE, DELETE)
	hasDML := strings.Contains(sql, "INSERT") ||
		strings.Contains(sql, "UPDATE") ||
		strings.Contains(sql, "DELETE")

	return hasDML
}

// hasComplexNesting checks for potentially unsafe nested query patterns
func hasComplexNesting(sql string) bool {
	sql = strings.ToUpper(sql)

	// Count nested parentheses depth - if too deep, it might be risky
	depth := 0
	maxDepth := 0
	for _, char := range sql {
		if char == '(' {
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
		} else if char == ')' {
			depth--
		}
	}

	// Allow reasonable nesting depth for WITH RECURSIVE patterns
	if maxDepth > 6 {
		return true
	}

	// Check for potentially problematic patterns
	problematicPatterns := []string{
		"UNION ALL.*SELECT.*FROM.*\\(", // Deeply nested UNION structures
		"EXISTS.*\\(.*EXISTS",          // Nested EXISTS clauses
		"IN.*\\(.*IN.*\\(",             // Nested IN clauses
	}

	for _, pattern := range problematicPatterns {
		matched, _ := regexp.MatchString(pattern, sql)
		if matched {
			return true
		}
	}

	return false
}

// isSafeForNesting determines if a query can safely be executed with nesting
func (e *executionContext) isSafeForNesting(sql string) bool {
	// Allow WITH RECURSIVE DML patterns that are proven safe
	if containsWithRecursiveDML(sql) && !hasComplexNesting(sql) {
		return true
	}

	// Allow DELETE/UPDATE queries ONLY if they have subqueries (indicating they're part of bulk operations)
	// Simple DELETE/UPDATE without subqueries should be blocked during active queries
	queryType := analyzeQueryType(sql)
	if queryType == QueryTypeDelete || queryType == QueryTypeUpdate {
		// Only allow if the query contains subqueries AND is not complex
		sql = strings.ToUpper(sql)
		hasSubquery := strings.Contains(sql, "SELECT") && (strings.Contains(sql, "WHERE") || strings.Contains(sql, "FROM"))
		if hasSubquery && !hasComplexNesting(sql) {
			return true
		}
	}

	// Default to not allowing nesting for safety
	return false
}

// canAllowThisQuery determines if the current query can be executed despite query being active
func (e *executionContext) canAllowThisQuery(sql string) bool {
	// If no query is currently active, always allow
	if !e.queryState.active {
		return true
	}

	// If a query is active, check if this query can safely nest
	return e.isSafeForNesting(sql)
}
