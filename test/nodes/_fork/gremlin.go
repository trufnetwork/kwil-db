package main

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/trufnetwork/kwil-db/common"
	"github.com/trufnetwork/kwil-db/common/functions"
	"github.com/trufnetwork/kwil-db/core/types/serialize"
	"github.com/trufnetwork/kwil-db/core/types/transactions"
	"github.com/trufnetwork/kwil-db/extensions/auth"
	"github.com/trufnetwork/kwil-db/extensions/consensus"
	"github.com/trufnetwork/kwil-db/extensions/resolutions"
	"github.com/trufnetwork/kwil-db/extensions/resolutions/credit"
)

func init() {
	consensus.RegisterHardfork(&consensus.Hardfork{
		// This is for testing of the fields that support extensions-based forks:
		//  - a consensus parameter update changing app version to 1, causing an
		//    appHash divergence if not coordinated
		//  - a new tx payload ("noop"), with a nominal cost and a well-defined
		//    acceptable payload, but no app state changes.
		//  - a one time state mod at activation, which credits a hard coded
		//    account with a small but observable amount

		Name: "gremlin", // the name is not exported for this test fork

		AuthUpdates: []*consensus.AuthMod{
			{
				Name:      "ed25519+sha256",
				Operation: auth.ModAdd,
				Authn:     auth.Ed22519Sha256Authenticator{},
			},
		},

		// modify the "credit_account" resolution used by the eth event oracle
		// so that it takes only >1/6 of the validators to affect a credit.
		ResolutionUpdates: []*consensus.ResolutionMod{
			{
				Name:      credit.CreditAccountEventType,
				Operation: resolutions.ModUpdate,
				Config: &resolutions.ResolutionConfig{
					RefundThreshold:       big.NewRat(1, 6),
					ConfirmationThreshold: big.NewRat(1, 12),
				},
			},
		},

		ParamsUpdates: &consensus.ParamUpdates{
			Version: &consensus.VersionParams{
				App: 9876,
			},
		},

		TxPayloads: []consensus.Payload{
			{
				Type:  transactions.PayloadType("noop"),
				Route: &gremlinNoopRoute{},
			},
		},

		Encoders: []*serialize.Codec{ // we need a BroadcastRaw to actually test this
			{
				Name: "gob",
				Type: 1234 + serialize.EncodingTypeCustom,
				Encode: func(a any) ([]byte, error) {
					var b bytes.Buffer
					if err := gob.NewEncoder(&b).Encode(a); err != nil {
						return nil, err
					}
					return b.Bytes(), nil
				},
				Decode: func(b []byte, a any) error {
					r := bytes.NewReader(b)
					return gob.NewDecoder(r).Decode(a)
				},
			},
		},

		StateMod: func(ctx context.Context, a *common.App) error {
			acct, _ := hex.DecodeString("dc18f4993e93b50486e3e54e27d91d57cee1da07")
			a.Service.Logger.S.Infof("========= gremlin crediting account %x =======", acct)
			return functions.Accounts.Credit(ctx, a.DB, acct, big.NewInt(42000))
		},
	})
}

type gremlinNoopRoute struct{}

func (d *gremlinNoopRoute) Name() string {
	return "noop"
}

func (d *gremlinNoopRoute) Price(context.Context, *common.App, *transactions.Transaction) (*big.Int, error) {
	return big.NewInt(42000), nil
}

func (d *gremlinNoopRoute) PreTx(_ *common.TxContext, _ *common.Service, tx *transactions.Transaction) (transactions.TxCode, error) {
	if len(tx.Body.Payload) != 1 {
		return transactions.CodeEncodingError, errors.New("incorrect payload length")
	}
	if tx.Body.Payload[0] != 0x42 {
		return transactions.CodeEncodingError, errors.New("incorrect payload")
	}

	return 0, nil
}

func (d *gremlinNoopRoute) InTx(*common.TxContext, *common.App, *transactions.Transaction) (transactions.TxCode, error) {
	return transactions.CodeOk, nil // no-op, no app state mods
}
