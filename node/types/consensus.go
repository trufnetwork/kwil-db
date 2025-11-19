package types

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/trufnetwork/kwil-db/core/types"
)

type ConsensusReset struct {
	ToHeight int64
	TxIDs    []Hash
}

func (cr ConsensusReset) String() string {
	return fmt.Sprintf("ConsensusReset{Height: %d}", cr.ToHeight)
}

func (cr ConsensusReset) Bytes() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint64(cr.ToHeight))
	binary.Write(buf, binary.LittleEndian, uint64(len(cr.TxIDs)))
	for _, txID := range cr.TxIDs {
		buf.Write(txID[:])
	}

	return buf.Bytes()
}

func (cr ConsensusReset) MarshalBinary() ([]byte, error) {
	return cr.Bytes(), nil
}

func (cr *ConsensusReset) UnmarshalBinary(data []byte) error {
	if len(data) < 16 {
		return errors.New("invalid ConsensusReset data")
	}

	buf := bytes.NewBuffer(data)

	var height uint64
	if err := binary.Read(buf, binary.LittleEndian, &height); err != nil {
		return err
	}
	cr.ToHeight = int64(height)

	var numTxIDs uint64
	if err := binary.Read(buf, binary.LittleEndian, &numTxIDs); err != nil {
		return err
	}
	cr.TxIDs = make([]Hash, numTxIDs)

	for i := range cr.TxIDs {
		if _, err := buf.Read(cr.TxIDs[i][:]); err != nil {
			return err
		}
	}

	return nil
}

// In scenarios where the leader is trying to catchup, there is a possibility
// that the leader syncs to a height which is far behind the network's best height,
// and leader starts proposing the blocks from that height. In such cases, the
// Validators upon hearing a new block proposal for already committed block should
// respond to the leader with a Nack, providing leader feedback about it's status
// including the blk proposal of the height it is at, with the leader's signature.
// Leader can use this feedback to eventually catch up with the network.

// NackStatus describes the reason for a nack response.
type NackStatus string

const (
	// If the block validation fails either due to invalid header info such as
	// AppHash or the ValidatorHash or Invalid Merkle hash etc.
	NackStatusInvalidBlock NackStatus = "invalid_block"
	// If leader proposes a new block for an already committed height, indicating
	// that the leader may potentially be out of sync with the rest of the network.
	// This requires the validator to prove to the leader that the block is indeed
	// committed by sending the block header with the leaders signature in the Vote.
	NackStatusOutOfSync NackStatus = "out_of_sync"
	// other unknown miscellaneous reasons for nack
	NackStatusUnknown NackStatus = "unknown"
)

func (ns NackStatus) String() string {
	return string(ns)
}

// OutOfSyncProof is the evidence that the validator provides to the leader
// in the NACK vote to inform leader that it is out of sync with the network.
type OutOfSyncProof struct {
	// Header is the block header corresponding to the best height the node is at.
	Header *types.BlockHeader
	// Signature is the signature of the block header provided by the leader.
	Signature []byte
}

type AckRes struct {
	ACK bool
	// only required if ACK is false
	NackStatus *NackStatus
	Height     int64
	BlkHash    Hash
	// only required if ACK is true
	AppHash *Hash
	// optional, only required if the nack status is NackStatusOutOfSync
	OutOfSyncProof *OutOfSyncProof

	// Signature
	Signature *types.Signature
}

func (ar AckRes) ack() string {
	if ar.ACK {
		return "ACK"
	}
	return "nACK"
}

func (ar AckRes) String() string {
	if ar.ACK {
		return fmt.Sprintf("%s: height: %d, block %v, appHash %v", ar.ack(), ar.Height, ar.BlkHash, ar.AppHash)
	}
	return ar.ack()
}

func (ar *AckRes) Valid() error {
	if ar.ACK && ar.AppHash == nil {
		return errors.New("app hash is required for ACK")
	}

	if !ar.ACK {
		if ar.AppHash != nil {
			return errors.New("app hash is not allowed for nACK")
		}
		if ar.NackStatus == nil {
			return errors.New("nack status is required for nACK")
		}
		if *ar.NackStatus == NackStatusOutOfSync && ar.OutOfSyncProof == nil {
			return errors.New("proof is required for out of sync nack")
		}
	}

	if ar.Signature == nil {
		return errors.New("signature is required in the AckRes")
	}

	return nil
}

func (ar *AckRes) OutOfSync() (*OutOfSyncProof, bool) {
	if ar.ACK || ar.NackStatus == nil || *ar.NackStatus != NackStatusOutOfSync {
		return nil, false
	}

	// if the vote is a Nack with status NackOutOfSync, then it should contain the out-of-sync proof
	if ar.OutOfSyncProof == nil {
		return nil, false
	}
	return ar.OutOfSyncProof, true
}

func (ar AckRes) MarshalBinary() ([]byte, error) {
	// check if the AckRes is valid before marshalling
	// to ensure that we have all the required fields
	if err := ar.Valid(); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, ar.ACK); err != nil {
		return nil, fmt.Errorf("failed to write ACK: %v", err)
	}

	if err := binary.Write(&buf, binary.LittleEndian, uint64(ar.Height)); err != nil {
		return nil, fmt.Errorf("failed to write height in AckRes: %v", err)
	}

	if err := binary.Write(&buf, binary.LittleEndian, ar.BlkHash[:]); err != nil {
		return nil, fmt.Errorf("failed to write block hash in AckRes: %v", err)
	}

	if ar.ACK {
		// app hash
		if err := binary.Write(&buf, binary.LittleEndian, ar.AppHash[:]); err != nil {
			return nil, fmt.Errorf("failed to write app hash in AckRes: %v", err)
		}
	} else {
		// nack status
		if err := types.WriteCompactString(&buf, (*ar.NackStatus).String()); err != nil {
			return nil, fmt.Errorf("failed to write nack status in AckRes: %v", err)
		}
		// if nack status is NackStatusOutOfSync, write out of sync proof
		if *ar.NackStatus == NackStatusOutOfSync {
			// write header
			headerBts := types.EncodeBlockHeader(ar.OutOfSyncProof.Header)
			if err := types.WriteCompactBytes(&buf, headerBts); err != nil {
				return nil, fmt.Errorf("failed to write header in AckRes: %v", err)
			}
			// write signature
			if err := types.WriteCompactBytes(&buf, ar.OutOfSyncProof.Signature); err != nil {
				return nil, fmt.Errorf("failed to write signature in AckRes: %v", err)
			}
		}
	}

	sigBts := ar.Signature.Bytes()
	if err := types.WriteCompactBytes(&buf, sigBts); err != nil {
		return nil, fmt.Errorf("failed to write signature in AckRes: %v", err)
	}
	return buf.Bytes(), nil
}

func (ar *AckRes) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)

	if err := binary.Read(buf, binary.LittleEndian, &ar.ACK); err != nil {
		return fmt.Errorf("failed to read ACK: %v", err)
	}

	var height uint64
	if err := binary.Read(buf, binary.LittleEndian, &height); err != nil {
		return fmt.Errorf("failed to read height in AckRes: %v", err)
	}
	ar.Height = int64(height)

	if _, err := buf.Read(ar.BlkHash[:]); err != nil {
		return fmt.Errorf("failed to read block hash in AckRes: %v", err)
	}

	if ar.ACK {
		// Read app hash
		var appHash Hash
		if _, err := buf.Read(appHash[:]); err != nil {
			return fmt.Errorf("failed to read app hash in AckRes: %v", err)
		}
		ar.AppHash = &appHash
	} else {
		// Read nack status
		ns, err := types.ReadCompactString(buf)
		if err != nil {
			return fmt.Errorf("failed to read nack status in AckRes: %v", err)
		}
		nackStatus := NackStatus(ns)
		ar.NackStatus = &nackStatus

		// if nack status is NackStatusOutOfSync, read out of sync proof
		if *ar.NackStatus == NackStatusOutOfSync {
			headerBts, err := types.ReadCompactBytes(buf)
			if err != nil {
				return fmt.Errorf("failed to read header in AckRes: %v", err)
			}
			header, err := types.DecodeBlockHeader(bytes.NewBuffer(headerBts))
			if err != nil {
				return fmt.Errorf("failed to decode header in AckRes: %v", err)
			}

			sigBts, err := types.ReadCompactBytes(buf)
			if err != nil {
				return fmt.Errorf("failed to read signature in AckRes: %v", err)
			}

			ar.OutOfSyncProof = &OutOfSyncProof{
				Header:    header,
				Signature: sigBts,
			}
		}
	}

	sigBts, err := types.ReadCompactBytes(buf)
	if err != nil {
		return fmt.Errorf("failed to read signature in AckRes: %v", err)
	}
	sig := &types.Signature{}
	if _, err := sig.ReadFrom(bytes.NewReader(sigBts)); err != nil {
		return fmt.Errorf("failed to decode signature in AckRes: %v", err)
	}
	ar.Signature = sig

	return nil
}

type DiscoveryRequest struct{}

func (dr DiscoveryRequest) String() string {
	return "DiscoveryRequest"
}

type DiscoveryResponse struct {
	BestHeight int64
}

func (dr DiscoveryResponse) String() string {
	return fmt.Sprintf("DiscoveryMsg{BestHeight: %d}", dr.BestHeight)
}

func (dr DiscoveryResponse) Bytes() []byte {
	return binary.LittleEndian.AppendUint64(nil, uint64(dr.BestHeight))
}

func (dr DiscoveryResponse) MarshalBinary() ([]byte, error) {
	return dr.Bytes(), nil
}

func (dr *DiscoveryResponse) UnmarshalBinary(data []byte) error {
	if len(data) != 8 {
		return errors.New("invalid DiscoveryMsg data")
	}
	dr.BestHeight = int64(binary.LittleEndian.Uint64(data))
	return nil
}
