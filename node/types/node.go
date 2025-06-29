package types

import (
	"github.com/trufnetwork/kwil-db/core/types"
)

type HexBytes = types.HexBytes

type Role int

const (
	RoleLeader Role = iota
	RoleValidator
	RoleSentry
)

func (r Role) String() string {
	switch r {
	case RoleLeader:
		return "leader"
	case RoleValidator:
		return "validator"
	case RoleSentry:
		return "sentry"
	default:
		return "unknown"
	}
}
