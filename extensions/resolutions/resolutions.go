// package resolutions contains the interface and registration for resolution types.
package resolutions

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/types"
)

// registeredResolutions is a map of all registered resolutions.
var registeredResolutions = make(map[string]ResolutionConfig)

// ModOperation is the type used to enumerate different resolution modifications
type ModOperation int8

// Resolutions may be removed, updated, or added.
const (
	ModRemove ModOperation = iota - 1
	ModUpdate
	ModAdd
)

// RegisterResolution registers a resolution with the Kwil network.
func RegisterResolution(name string, mod ModOperation, resolution ResolutionConfig) error {
	name = strings.ToLower(name)
	if _, ok := registeredResolutions[name]; ok {
		switch mod {
		case ModAdd:
			return fmt.Errorf("resolution with name %s already registered: ", name)
		case ModRemove:
			delete(registeredResolutions, name)
		case ModUpdate:
			registeredResolutions[name] = resolution
		}
		return nil
	}
	switch mod {
	case ModRemove, ModUpdate:
		return fmt.Errorf("resolution does not exist to modify (%d)", mod)
	default: // add
	}

	if resolution.RefundThreshold == nil {
		resolution.RefundThreshold = big.NewRat(1, 1) // 100%
	}
	if resolution.ConfirmationThreshold == nil {
		resolution.ConfirmationThreshold = big.NewRat(2, 3) // 66.67%
	}
	if resolution.ExpirationPeriod < 1 {
		resolution.ExpirationPeriod = 24 * time.Hour // 1 day
	}

	registeredResolutions[name] = resolution
	return nil
}

// GetResolution returns a resolution by its name.
func GetResolution(name string) (ResolutionConfig, error) {
	resolution, ok := registeredResolutions[strings.ToLower(name)]
	if !ok {
		return ResolutionConfig{}, fmt.Errorf("resolution with name %s not found", name)
	}

	return resolution, nil
}

// ListResolutions returns a list of all registered resolutions.
func ListResolutions() []string {
	resolutions := make([]string, 0, len(registeredResolutions))
	for name := range registeredResolutions {
		resolutions = append(resolutions, name)
	}

	return resolutions
}

// ResolutionConfig is a configuration for a type of resolution.
// It can be used to define resolutions that a Kwil network can vote
// on, and define the resulting logic if the resolution receives the
// required number of votes.
type ResolutionConfig struct {
	// RefundThreshold is the required vote percentage threshold for
	// all voters on a resolution to be refunded the gas costs
	// associated with voting. This allows for resolutions that have
	// not received enough votes to pass to refund gas to the voters
	// that have voted on the resolution. For a 1/3rds threshold,
	// >=1/3rds of the voters must vote for the resolution for
	// refunds to occur. If this threshold is not met, voters will
	// not be refunded when the resolution expires. The number must
	// be a fraction between 0 and 1. If this field is nil, it will
	// default to only refunding voters when the resolution is confirmed.
	RefundThreshold *big.Rat
	// ConfirmationThreshold is the required vote percentage
	// threshold for whether a resolution is confirmed. In a 2/3rds
	// threshold, >=2/3rds of the voters must vote for the resolution
	// for it to be confirmed. Voters will also be refunded if this
	// threshold is met, regardless of the refund threshold. The
	// number must be a fraction between 0 and 1. If this field is
	// nil, it will default to 2/3.
	ConfirmationThreshold *big.Rat
	// ExpirationPeriod is the duration for which the resolution will
	// be valid for before it expires. This is applied additively to the
	// block timestamp in the header when the resolution is created.
	// If not set, the resolution expiry is defaulted to 86400 secs (1 day)
	ExpirationPeriod time.Duration
	// ResolveFunc is a function that is called once a resolution has
	// received a required number of votes, as defined by the
	// ConfirmationThreshold. It is given a readwrite database
	// connection and the information for the resolution that has
	// been confirmed. All nodes will call this function as a part of
	// block execution. It is therefore expected that the function is
	// deterministic, regardless of a node's local configuration.
	ResolveFunc ResolveFunc
}

// ResolveFunc is a function that is called once a resolution has
// received a required number of votes.
type ResolveFunc func(ctx context.Context, app *common.App, resolution *Resolution, block *common.BlockContext) error

// Resolution contains information for a resolution that can be voted
// on.
type Resolution struct {
	// ID is the unique identifier for the resolution. It is a UUID
	// that is deterministically generated from the body of the
	// resolution.
	ID *types.UUID
	// Body is the content of the resolution. It can hold any
	// arbitrary data that is relevant to the resolution.
	Body []byte
	// Type is the type of the resolution. It is used to determine
	// the logic for the resolution.
	Type string
	// Expiration is the timestamp at which the resolution is set to
	// Expire.
	Expiration time.Time
	// Expiration          int64
	// ApprovedPower is the total power of the voters that have
	// approved the resolution.
	ApprovedPower int64
	// Voters is a list of voters that have voted on the resolution.
	// This includes the proposer of the resolution.
	Voters []*types.Validator
	// Proposer is the voter that proposed the resolution body.
	Proposer *types.Validator
}
