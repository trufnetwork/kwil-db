package validation

// max name lengths
const (
	// postgres limits identifiers to 63, but we need to reserve space
	// for prefixes. 64 is a reasonable limit.
	MAX_IDENT_NAME_LENGTH = 64
)

// table restrictions
const (
	MAX_TABLE_COUNT           = 100
	MAX_COLUMNS_PER_TABLE     = 50 // per table
	MAX_ATTRIBUTES_PER_COLUMN = 5  // per column
)

// index restrictions
const (
	MAX_INDEX_COUNT   = 100
	MAX_INDEX_COLUMNS = 5
)

// query restrictions
const (
	MAX_QUERY_COUNT     = 400
	MAX_PARAM_PER_QUERY = 50
	MAX_WHERE_PER_QUERY = 3
)

// role restrictions
const (
	MAX_ROLE_COUNT = 50
)

// wallets
const (
	MIN_WALLET_LENGTH = 42
	MAX_WALLET_LENGTH = 44
)
