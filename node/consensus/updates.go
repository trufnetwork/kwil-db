package consensus

import (
	"bytes"
	"context"
	"encoding"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/extensions/resolutions"
)

const (
	ParamUpdatesResolutionType = "param_updates"
)

type ParamUpdatesDeclaration struct {
	// Description is an informative description of the resolution, and it
	// serves to make it a unique resolution even if the ParamUpdates have been
	// proposed in a prior resolution.
	Description string // e.g. "Increase max votes (KWIL Consensus change #1)"

	// ParamUpdates is the actual updates to be made to the Kwil network.
	ParamUpdates types.ParamUpdates
}

func init() {
	err := resolutions.RegisterResolution(ParamUpdatesResolutionType, resolutions.ModAdd, ParamUpdatesResolution)
	if err != nil {
		panic(err)
	}
}

var ParamUpdatesResolution = resolutions.ResolutionConfig{
	ConfirmationThreshold: big.NewRat(1, 2),   // > 50%
	ExpirationPeriod:      7 * 24 * time.Hour, // 1 week
	ResolveFunc: func(ctx context.Context, app *common.App, resolution *resolutions.Resolution, block *common.BlockContext) error {
		// a resolution with an invalid body should be rejected before this
		var pud ParamUpdatesDeclaration
		err := pud.UnmarshalBinary(resolution.Body)
		if err != nil {
			return err
		}

		app.Service.Logger.Info("Applying param updates", "description", pud.Description, "paramUpdates", pud.ParamUpdates)

		// block.ChainContext.NetworkUpdates <= pud.ParamUpdates
		if block.ChainContext.NetworkUpdates == nil {
			block.ChainContext.NetworkUpdates = make(types.ParamUpdates, len(pud.ParamUpdates))
		}
		block.ChainContext.NetworkUpdates.Merge(pud.ParamUpdates)
		return nil
	},
}

var _ encoding.BinaryMarshaler = ParamUpdatesDeclaration{}
var _ encoding.BinaryMarshaler = (*ParamUpdatesDeclaration)(nil)

const pudVersion = 0

func (pud ParamUpdatesDeclaration) MarshalBinary() ([]byte, error) {
	buf := &bytes.Buffer{}
	// version uint16
	binary.Write(buf, types.SerializationByteOrder, uint16(pudVersion))
	// description
	types.WriteString(buf, pud.Description)
	// param updates
	updBts, err := pud.ParamUpdates.MarshalBinary()
	if err != nil {
		return nil, err
	}
	types.WriteBytes(buf, updBts) // could just be buf.Write(updBts) since this is the end
	return buf.Bytes(), nil
}

var _ encoding.BinaryUnmarshaler = (*ParamUpdatesDeclaration)(nil)

func (pud *ParamUpdatesDeclaration) UnmarshalBinary(b []byte) error {
	buf := bytes.NewBuffer(b)
	// version uint16
	var version uint16
	binary.Read(buf, types.SerializationByteOrder, &version)
	if version != pudVersion {
		return fmt.Errorf("invalid version %d", version)
	}
	// description
	desc, err := types.ReadString(buf)
	if err != nil {
		return err
	}
	// param updates
	updBts, err := types.ReadBytes(buf)
	if err != nil {
		return err
	}
	var pu types.ParamUpdates
	if err := pu.UnmarshalBinary(updBts); err != nil {
		return err
	}

	pud.Description = desc
	pud.ParamUpdates = pu

	return nil
}
