package voting

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/extensions/resolutions"
)

// this file implements the voting logic for validator approvals

const (
	ValidatorJoinEventType   = "validator_join"
	ValidatorRemoveEventType = "validator_remove"
)

func init() {
	err := resolutions.RegisterResolution(ValidatorJoinEventType, resolutions.ModAdd, resolutions.ResolutionConfig{
		ConfirmationThreshold: big.NewRat(2, 3),
		ResolveFunc: func(ctx context.Context, app *common.App, resolution *resolutions.Resolution, block *common.BlockContext) error {
			joinReq := &UpdatePowerRequest{}
			if err := joinReq.UnmarshalBinary(resolution.Body); err != nil {
				return fmt.Errorf("failed to unmarshal join request: %w", err)
			}

			app.Service.Logger.Info("Updating validator power", "pubKey", joinReq.PubKey,
				"pubKeyType", joinReq.PubKeyType, "power", joinReq.Power)

			return app.Validators.SetValidatorPower(ctx, app.DB, joinReq.PubKey, joinReq.PubKeyType, joinReq.Power)
		},
	})
	if err != nil {
		panic(err)
	}

	err = resolutions.RegisterResolution(ValidatorRemoveEventType, resolutions.ModAdd, resolutions.ResolutionConfig{
		ConfirmationThreshold: big.NewRat(2, 3),
		ResolveFunc: func(ctx context.Context, app *common.App, resolution *resolutions.Resolution, block *common.BlockContext) error {
			removeReq := &UpdatePowerRequest{}
			if err := removeReq.UnmarshalBinary(resolution.Body); err != nil {
				return fmt.Errorf("failed to unmarshal remove request: %w", err)
			}
			if removeReq.Power != 0 {
				// this should never happen since UpdatePowerRequest is only used for internal communication
				// between modules. Removes are sent from the client in a separate message.
				return errors.New("remove request with non-zero power")
			}

			app.Service.Logger.Info("Removing validator", "pubKey", removeReq.PubKey, "pubKeyType", removeReq.PubKeyType)

			return app.Validators.SetValidatorPower(ctx, app.DB, removeReq.PubKey, removeReq.PubKeyType, 0)
		},
	})
	if err != nil {
		panic(err)
	}
}

// UpdatePowerRequest is a request to update a validator's power.
type UpdatePowerRequest struct {
	PubKey     []byte
	PubKeyType crypto.KeyType
	Power      int64
}

const updatePowerRequestVersion = 0

// MarshalBinary returns the binary representation of the join request
// It is deterministic
func (j *UpdatePowerRequest) MarshalBinary() ([]byte, error) {
	buf := &bytes.Buffer{}
	if err := binary.Write(buf, types.SerializationByteOrder, uint16(updatePowerRequestVersion)); err != nil {
		return nil, err
	}
	if err := types.WriteCompactBytes(buf, j.PubKey); err != nil {
		return nil, err
	}
	if err := types.WriteCompactString(buf, j.PubKeyType.String()); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, types.SerializationByteOrder, j.Power); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalBinary unmarshals the join request from its binary representation
func (j *UpdatePowerRequest) UnmarshalBinary(data []byte) error {
	buf := bytes.NewReader(data)
	var err error
	var version uint16
	if err = binary.Read(buf, types.SerializationByteOrder, &version); err != nil {
		return err
	}
	if version != updatePowerRequestVersion {
		return fmt.Errorf("invalid version %d", version)
	}
	if j.PubKey, err = types.ReadCompactBytes(buf); err != nil {
		return err
	}
	pubKeyType, err := types.ReadCompactString(buf)
	if err != nil {
		return err
	}
	j.PubKeyType = crypto.KeyType(pubKeyType)
	return binary.Read(buf, types.SerializationByteOrder, &j.Power)
}
