// Package consensus is used to apply customized rules for activation of
// hardforks defined in the genesis file.
//
// The goal of this as an extension is to minimize the need to modify internal
// kwild code to define coordinated changes to certain common or likely
// consensus rules.
//
// main capabilities:
//   - new transaction payload types, or payload versions
//   - modifications (add/remove/update) to the registered authenticators
//   - modifications to registered resolutions (governance-initiated transactions)
//   - configurable / pluggable serialization scheme
//   - consensus engine parameter updates, such as block size or other limits
//   - one time actions at activation height (see ethereum's TheDAO state changes),
//     like transferring or minting tokens, decreed validator set updates, special
//     dataset modifications - resolution-like actions that must be in tandem with
//     code and app logic change.
//
// The genesis files forks section may reference canonical forks defined in
// kwild code with named helpers like IsMyLogicV2(height uint64) switching
// between logic at any location. That requires kwild code updates; this
// consensus extension package aims to allow definition of custom hard fork
// aliases, that may modify the logic in certain well-defined ways. Arbitrary
// changes to kwild consensus logic may require changes to kwild internals (as
// is the standard approach in most blockchains), or adding new capabilities to
// this consensus extensions package and how kwild uses it to facilitate new
// types of live changes.
package consensus

import (
	"context"
	"fmt"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/core/types/serialize"
	"github.com/trufnetwork/kwil-db/extensions/resolutions"

	authExt "github.com/trufnetwork/kwil-db/extensions/auth"
)

// Need fork order defined for unambiguous application of many at same height,
// such as is common with genesis on a new network.

// Hardforks contains all known hardfork definitions.  Include both
// canonical/kwild and extensions? This is just a list. When kwild loads
// genesis.json, it locates the named hardforks in this registry.
var Hardforks = map[string]*Hardfork{}

// RegisterHardfork registers a hardfork definition by the name that should be
// expected in the genesis file. The payload type is registered in the
// transaction package, but the route is enabled in the tx app at activation.
func RegisterHardfork(hf *Hardfork) {
	if _, have := Hardforks[hf.Name]; have {
		panic(fmt.Sprintf("already have hardfork %q", hf.Name))
	}
	Hardforks[hf.Name] = hf

	for _, newPayload := range hf.TxPayloads {
		types.RegisterPayload(newPayload.Type)
		// NOTE: newPayload.Route stays in the []Hardfork.TxPayloads until
		// activation, when TxApp/ABCI enable the tx route.
	}
}

// Hardfork specifies the fundamental changes affected by a named hardfork. If a
// field is nil or the zero value for the type, that particular change is not
// part of the hardfork's definition. When the hardfork is registered, only the
// defined changes are applied in the relevant parts of kwild.
//
// An instance of this type is designed initially for the simplest coordination,
// height, using the common/chain package to specify activation height. However,
// more generally, the Hardfork struct exposes a set of well-defined types of
// changes that may be implemented via the extension system *without modifying
// kwild code*. Such a change may be part of a resolution approved with the
// voting system, in which case it would be applied when threshold is reached
// rather than when an activation height is reached.
type Hardfork struct {
	// Name is the hard fork's code name.
	Name string
	// NOTE: Activation height is specified by genesis.json (or other dynamic
	// methods like signaling / voting). This struct defines the changes.

	// Optional consensus logic overrides below.  All of these will require
	// dynamic kwil-db support, such as registering new encoders and transaction
	// payloads, submitting consensus parameter updates to the consensus engine,
	// applying state adjustments at activation height in ABCI / TxApp, etc.

	// CATEGORY 1: registered functionality changes: payloads, authenticators,
	// resolutions, and data serialization schema (codecs).

	// TxPayloads specifies new transaction payload to recognize at activation.
	// To modify an existing payload in a backward incompatible way, instead
	// create a new version of the payload such as PayloadTypeExecuteActionV2.
	// Any such changes would also be accompanied by tooling updates.
	// TODO: consider payload removal/invalidation and replace.
	TxPayloads []Payload // Type() and tx app Route() implementation

	// AuthUpdates are updates (add/remove/change) to known Authenticators for
	// signature verification.
	AuthUpdates []*AuthMod

	// ResolutionUpdates are coordinated changes to the resolutions extension.
	// They may be added, modified (redefined), or removed at activation. Any
	// have the potential to break consensus, and should be done with a Hardfork.
	ResolutionUpdates []*ResolutionMod

	// Encoders are new encoder types to register *at activation height* for
	// core/types/serialize.Encode/Decode e.g. Borsch instead of RLP.
	// EncodingTypeCustom offset should be used as the first possible external
	// codec's type to leave space for more kwild canonical codecs in the
	// future. Choose an encoding type that does not collide with other codecs.
	// Any such changes would also be accompanied by tooling updates.
	Encoders []*serialize.Codec

	// CATEGORY 2: One time updates.

	// ParamsUpdates are updates to the consensus engine parameters that should
	// go into affect at after the activation height (returned to the consensus
	// engine when finalizing the block at this height). For example, a block
	// size change.
	ParamsUpdates types.ParamUpdates

	// StateMod is triggered at activation. It can do anything, one time. For
	// instance, arbitrary change to application state via the Engine or more
	// directly to the DB may be made at the end of block at the activation
	// height. This is to be called inside the outer transaction of activation
	// block, so changes to state are captured in the normal apphash diff. This
	// is a reasonable capability for a hardfork to make state changes outside
	// of transaction execution, but most such changes can probably be achieved
	// through the resolution system and voting. Doing it in a hardfork would be
	// needed if there are other changes (either baked in to kwild or in the
	// above fields) that should be done in concert with the fork.
	StateMod func(context.Context, *common.App) error
}

// VersionParams contains an update to the application protocol version to give
// to cometbft. While not required, this can help proactively signal a new
// application version with altered logic that affects state machine. For
// instance, a coordinated height-based upgrade to consensus logic could be
// accompanied by an update to this version to ensure all nodes made the same
// update at the same height. Canonical configurable hard fork activations on
// the other hand would not do this; only hard-coded changes.
//
// In the case of new major release that has incompatible logic, a global
// AppVersion would be bumped (compared to the old network) at genesis instead
// of using this update, which is to change a live network.
type VersionParams struct {
	App uint64 `json:"app"`
}

// ResolutionMod defines a modification to a consensus resolution used by the
// oracle system. A modification may be adding a new resolution, or modifying or
// removing an existing resolution.
type ResolutionMod struct {
	Name      string
	Operation resolutions.ModOperation
	Config    *resolutions.ResolutionConfig
}

// AuthMod defines a modification to an authenticator used to verify signatures.
// A modification may be adding a new authenticator, or modifying or removing an
// existing authenticator.
type AuthMod struct {
	Name      string
	Operation authExt.ModOperation
	Authn     auth.Authenticator
}
