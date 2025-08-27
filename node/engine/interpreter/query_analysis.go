package interpreter

import (
	"regexp"
	"strings"
)

// Simplified regexes for technical safety only
var (
	// SQL injection patterns - multiple statements separated by semicolons
	multipleStatementsRe = regexp.MustCompile(`(?i);\s*(DROP|ALTER|CREATE|TRUNCATE|DELETE|UPDATE|INSERT)\b`)

	// System function calls that could be non-deterministic
	systemFunctionRe = regexp.MustCompile(`(?i)\b(system|pg_read_file|pg_write_file|pg_execute|copy|\\)\b`)
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
	active    bool
	queryType QueryType
	sql       string
}

// preprocessSQL strips SQL comments and string literals to avoid false positives
func preprocessSQL(sql string) string {
	var result strings.Builder
	inSingleQuote := false
	inDoubleQuote := false
	inMultiLineComment := false

	for i := 0; i < len(sql); i++ {
		char := sql[i]

		// Handle multi-line comment start
		if !inSingleQuote && !inDoubleQuote && !inMultiLineComment &&
			i < len(sql)-1 && sql[i:i+2] == "/*" {
			inMultiLineComment = true
			result.WriteByte(' ') // Replace with space to maintain word boundaries
			i++                   // Skip the '*'
			continue
		}

		// Handle multi-line comment end
		if inMultiLineComment && i < len(sql)-1 && sql[i:i+2] == "*/" {
			inMultiLineComment = false
			result.WriteByte(' ') // Replace with space to maintain word boundaries
			i++                   // Skip the '/'
			continue
		}

		// Handle single-line comment
		if !inSingleQuote && !inDoubleQuote && !inMultiLineComment &&
			i < len(sql)-1 && sql[i:i+2] == "--" {
			result.WriteByte(' ') // Replace with space to maintain word boundaries
			// Skip to end of line
			for i < len(sql) && sql[i] != '\n' {
				i++
			}
			if i < len(sql) {
				result.WriteByte('\n') // Preserve line breaks
			}
			continue
		}

		// Skip content inside comments
		if inMultiLineComment {
			continue
		}

		// Handle dollar-quoted PostgreSQL literals ($tag$...$tag$ or $...$)
		if char == '$' && !inSingleQuote && !inDoubleQuote {
			// Find the complete dollar quote tag
			tagEnd := i + 1
			for tagEnd < len(sql) && sql[tagEnd] != '$' {
				tagEnd++
			}
			if tagEnd < len(sql) { // Found closing $ of tag
				tag := sql[i : tagEnd+1] // e.g., "$", "$tag$"
				// Skip past the opening tag
				i = tagEnd
				result.WriteByte(' ') // Replace with space to maintain word boundaries
				// Find the matching closing tag
				for i+len(tag) < len(sql) {
					if sql[i+1:i+1+len(tag)] == tag {
						// Found matching closing tag
						i += len(tag) // Skip past the closing tag
						break
					}
					i++
					if sql[i] == '\n' {
						result.WriteByte('\n') // Preserve line breaks
					}
				}
				continue
			}
		}

		// Handle string literals
		if char == '\'' && !inDoubleQuote {
			if inSingleQuote && i < len(sql)-1 && sql[i+1] == '\'' {
				// Escaped single quote
				i++ // Skip the next quote
			} else {
				inSingleQuote = !inSingleQuote
			}
			if !inSingleQuote {
				result.WriteByte(' ') // Replace string content with space
			}
			continue
		}

		// Handle double-quoted identifiers with proper escape handling
		if char == '"' && !inSingleQuote {
			if inDoubleQuote && i < len(sql)-1 && sql[i+1] == '"' {
				// Escaped double quote ("") - consume both quotes but stay in double-quote mode
				i++ // Skip the next quote
			} else {
				// Non-escaped double quote - toggle state
				inDoubleQuote = !inDoubleQuote
				if !inDoubleQuote {
					result.WriteByte(' ') // Replace string content with space
				}
			}
			continue
		}

		// Skip content inside strings
		if inSingleQuote || inDoubleQuote {
			continue
		}

		// Regular character - add to result
		result.WriteByte(char)
	}

	return result.String()
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

// hasTechnicalViolations checks for patterns that would cause actual technical failures
// Only blocks patterns that could cause consensus safety issues or connection problems
func hasTechnicalViolations(sql string) bool {
	// Strip comments and string literals before analysis
	clean := preprocessSQL(sql)

	// Check for SQL injection patterns (multiple statements)
	if multipleStatementsRe.MatchString(clean) {
		return true
	}

	// Check for system function calls that could be non-deterministic
	if systemFunctionRe.MatchString(clean) {
		return true
	}

	// Check for malformed parentheses (could cause parser issues)
	depth := 0
	for _, char := range clean {
		if char == '(' {
			depth++
		} else if char == ')' {
			depth--
			// Malformed SQL with mismatched parentheses
			if depth < 0 {
				return true
			}
		}
	}

	// Unclosed parentheses
	if depth != 0 {
		return true
	}

	return false
}

// isSafeForNesting determines if a query can safely be executed with nesting
// Now allows all PostgreSQL-compatible patterns, only blocking technical violations
func (e *executionContext) isSafeForNesting(sql string) bool {
	// Allow all queries that don't have technical violations
	// This removes performance-based restrictions while maintaining consensus safety
	return !hasTechnicalViolations(sql)
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
