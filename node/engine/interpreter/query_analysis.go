package interpreter

import (
	"regexp"
	"strings"
)

// Precompiled regexes for efficient pattern matching
var (
	subqueryRe = regexp.MustCompile(`(?is)\(\s*SELECT\b`)

	// Same-statement WITH RECURSIVE + DML detection (no intervening semicolon)
	reWithRecursiveDMLSameStmt = regexp.MustCompile(`(?is)\bWITH\s+RECURSIVE\b[^;]*\b(INSERT|UPDATE|DELETE)\b`)

	// Problematic nesting patterns - precompiled with case-insensitive and dotall flags
	// These patterns detect genuinely dangerous constructs while avoiding false positives on WITH RECURSIVE
	problematicNestRes = []*regexp.Regexp{
		regexp.MustCompile(`(?is)SELECT.*FROM.*\(.*SELECT.*FROM.*\(.*SELECT`), // Deeply nested SELECT statements (3+ levels)
		regexp.MustCompile(`(?is)EXISTS\s*\([^)]*EXISTS`),                     // Nested EXISTS clauses
		regexp.MustCompile(`(?is)IN\s*\([^)]*IN\s*\(`),                        // Nested IN clauses
		regexp.MustCompile(`(?is)IN\s*\([^)]*SELECT[^)]*\bIN\b`),              // IN with sub-SELECT containing IN
		regexp.MustCompile(`(?is)UNION\s+ALL.*SELECT.*FROM.*\(.*SELECT`),      // Complex UNION structures
	}
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

// containsWithRecursiveDML checks if the query contains WITH RECURSIVE in a DML context
func containsWithRecursiveDML(sql string) bool {
	// First preprocess to strip comments and string literals
	clean := preprocessSQL(sql)

	// Enforce same-statement WITH RECURSIVE + DML
	return reWithRecursiveDMLSameStmt.MatchString(clean)
}

// hasComplexNesting checks for potentially unsafe nested query patterns
func hasComplexNesting(sql string) bool {
	// Strip comments and string literals before analysis
	clean := preprocessSQL(sql)

	// Count nested parentheses depth - if too deep, it might be risky
	depth := 0
	maxDepth := 0
	for _, char := range clean {
		if char == '(' {
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
		} else if char == ')' {
			depth--
			// If depth goes negative, treat as complex (malformed or very complex)
			if depth < 0 {
				return true
			}
		}
	}

	// Allow reasonable nesting depth for WITH RECURSIVE patterns
	if maxDepth > 6 {
		return true
	}

	// Special handling for WITH RECURSIVE DML patterns
	if containsWithRecursiveDML(sql) {
		// Check for specific dangerous patterns that suggest data exfiltration
		// Pattern: accessing columns named 'secret', 'password', 'private' etc.
		suspiciousColumns := regexp.MustCompile(`(?i)\b(secret|password|private|confidential|key|token)\s*=`)
		if suspiciousColumns.MatchString(clean) {
			return true
		}

		// Check for deeply nested EXISTS patterns even in WITH RECURSIVE (like the security test)
		nestedExists := regexp.MustCompile(`(?is)EXISTS\s*\([^)]*EXISTS`)
		if nestedExists.MatchString(clean) {
			return true
		}

		// Allow normal bulk operation WITH RECURSIVE patterns
		return false
	}

	// For non-WITH RECURSIVE queries, apply full problematic pattern checks
	for _, regex := range problematicNestRes {
		if regex.MatchString(clean) {
			return true
		}
	}

	return false
}

// isSafeForNesting determines if a query can safely be executed with nesting
func (e *executionContext) isSafeForNesting(sql string) bool {
	clean := preprocessSQL(sql)
	// Allow WITH RECURSIVE DML patterns that are proven safe
	if containsWithRecursiveDML(sql) && !hasComplexNesting(sql) {
		return true
	}

	// Allow DELETE/UPDATE queries ONLY if they have subqueries (indicating they're part of bulk operations)
	// Simple DELETE/UPDATE without subqueries should be blocked during active queries
	queryType := analyzeQueryType(clean)
	if queryType == QueryTypeDelete || queryType == QueryTypeUpdate {
		// Only allow if the query contains subqueries AND is not complex
		hasSubquery := subqueryRe.MatchString(clean) // pattern: "( SELECT ... )"
		if hasSubquery && !hasComplexNesting(clean) {
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
