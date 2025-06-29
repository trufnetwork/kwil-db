package sec

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/core/sec"
	tptu "github.com/libp2p/go-libp2p/p2p/net/upgrader"
	"github.com/libp2p/go-libp2p/p2p/security/noise"

	"github.com/trufnetwork/kwil-db/core/log"
)

const SecChainID = "/noise-chainID"

// ScopedNoiseTransport wraps a Noise transport to add a chainID verification to
// the handshake.
type ScopedNoiseTransport struct {
	*noise.Transport
	chainID []byte
	logger  log.Logger
}

type SecConstructor func(id protocol.ID, privkey crypto.PrivKey, muxers []tptu.StreamMuxer) (sec.SecureTransport, error)

func NewScopedNoiseTransport(chainID string, logger log.Logger) (SecConstructor, string) {
	return func(id protocol.ID, privkey crypto.PrivKey, muxers []tptu.StreamMuxer) (sec.SecureTransport, error) {
		nt, err := noise.New(id, privkey, muxers)
		if err != nil {
			return nil, err
		}

		return &ScopedNoiseTransport{
			Transport: nt,
			chainID:   []byte(chainID),
			logger:    logger,
		}, nil
	}, SecChainID
}

var _ sec.SecureTransport = &ScopedNoiseTransport{}

func (cst *ScopedNoiseTransport) SecureInbound(ctx context.Context, conn net.Conn, pid peer.ID) (sec.SecureConn, error) {
	secConn, err := cst.Transport.SecureInbound(ctx, conn, pid)
	if err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	defer conn.SetDeadline(time.Time{})
	if err = cst.checkChainIDInbound(conn); err != nil {
		conn.Close()
		cst.logger.Warnf("Inbound peer failed chain ID check: %v", err)
		return nil, err
	}
	return secConn, nil
}

func (cst *ScopedNoiseTransport) SecureOutbound(ctx context.Context, conn net.Conn, pid peer.ID) (sec.SecureConn, error) {
	secConn, err := cst.Transport.SecureOutbound(ctx, conn, pid)
	if err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	defer conn.SetDeadline(time.Time{})
	if err = cst.checkChainIDOutbound(conn); err != nil {
		conn.Close()
		cst.logger.Warnf("Outbound peer failed chain ID check: %v", err)
		return nil, err
	}
	return secConn, nil
}

func (cst *ScopedNoiseTransport) checkChainIDOutbound(conn net.Conn) error {
	if err := writeMagicValue(conn, cst.chainID); err != nil {
		return err
	}

	remoteChainID, err := readMagicValue(conn)
	if err != nil {
		return fmt.Errorf("error reading chain ID: %v", err)
	}

	if !bytes.Equal(remoteChainID, cst.chainID) {
		return fmt.Errorf("chain id mismatch: %q != %q", string(remoteChainID), string(cst.chainID))
	}

	cst.logger.Debug("outbound peer chain id check passed", "chain id", string(cst.chainID), "remote", conn.RemoteAddr())

	return nil
}

func (cst *ScopedNoiseTransport) checkChainIDInbound(conn net.Conn) error {
	remoteChainID, err := readMagicValue(conn)
	if err != nil {
		return fmt.Errorf("error reading chain ID: %v", err)
	}

	if err = writeMagicValue(conn, cst.chainID); err != nil {
		return err
	}

	if !bytes.Equal(remoteChainID, cst.chainID) {
		return fmt.Errorf("chain id mismatch: %q != %q", string(remoteChainID), string(cst.chainID))
	}

	cst.logger.Debug("inbound peer chain id check passed", "chain id", string(cst.chainID), "remote", conn.RemoteAddr())

	return nil
}

func writeMagicValue(conn net.Conn, magicValue []byte) error {
	// Write the length as a uint16 (2 bytes)
	length := uint16(len(magicValue))
	if err := binary.Write(conn, binary.BigEndian, length); err != nil {
		return fmt.Errorf("error writing length: %w", err)
	}

	// Write the actual magic value
	if _, err := conn.Write(magicValue); err != nil { // conn.Write
		return fmt.Errorf("error writing magic value: %w", err)
	}

	return nil
}
func readMagicValue(conn net.Conn) ([]byte, error) {
	// Read the length (2 bytes)
	lengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lengthBuf); err != nil {
		return nil, fmt.Errorf("error reading length: %w", err)
	}
	length := binary.BigEndian.Uint16(lengthBuf)

	if length > 4096 {
		return nil, fmt.Errorf("magic value length too large (%d)", length)
	}

	// Read the actual magic value
	magicValue := make([]byte, length)
	if _, err := io.ReadFull(conn, magicValue); err != nil {
		return nil, fmt.Errorf("error reading magic value: %w", err)
	}

	return magicValue, nil
}
