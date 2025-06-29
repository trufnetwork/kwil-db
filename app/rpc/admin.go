package rpc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/trufnetwork/kwil-db/app/node/conf"
	"github.com/trufnetwork/kwil-db/app/shared/bind"
	"github.com/trufnetwork/kwil-db/config"
	adminclient "github.com/trufnetwork/kwil-db/node/admin"
)

const (
	rpcserverFlagName = "rpcserver"
)

// BindRPCFlags binds the RPC flags to the given command.
// This includes an rpcserver flag, and the TLS flags.
// These flags can be used to create an admin service client.
// The flags will be bound to all subcommands of the given command.
func BindRPCFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringP(rpcserverFlagName, "s", config.DefaultAdminRPCAddr, "admin RPC server address (either UNIX socket path or TCP address)")

	cmd.PersistentFlags().String("authrpc-cert", "", "kwild's TLS server certificate, required for HTTPS server")
	cmd.PersistentFlags().String("pass", "", "admin server password (alternative to mTLS with tlskey/tlscert)")
	cmd.PersistentFlags().String("tlskey", "auth.key", "TLS client key file to establish a mTLS (authenticated) connection")
	cmd.PersistentFlags().String("tlscert", "auth.cert", "TLS client certificate file for server to authenticate us")
}

// GetRPCServerFlag returns the RPC flag from the given command.
func GetRPCServerFlag(cmd *cobra.Command) (string, error) {
	return cmd.Flags().GetString(rpcserverFlagName)
}

// AdminSvcClient will return an admin service client based on the flags.
// The flags should be bound using the BindRPCFlags function.
func AdminSvcClient(ctx context.Context, cmd *cobra.Command) (*adminclient.AdminClient, error) {
	adminOpts := []adminclient.Opt{}

	// Get the RPC server address from the rpcserver flag. If it is not set and
	// the active config (from node config) is modified, then use the active config.
	var rpcServer string
	addrFlag := cmd.Flags().Lookup(rpcserverFlagName)
	cfgAddr := conf.ActiveConfig().Admin.ListenAddress
	if cfgAddr != config.DefaultAdminRPCAddr && !addrFlag.Changed {
		rpcServer = cfgAddr
	} else {
		rpcServer = addrFlag.Value.String()
	}

	// get the tls files
	// if one is specified, all must be specified
	// if none are specified, then we do not use tls
	if cmd.Flags().Changed("authrpc-cert") || cmd.Flags().Changed("tlskey") || cmd.Flags().Changed("tlscert") {
		kwildTLSCertFile, clientTLSKeyFile, clientTLSCertFile, err := getTLSFlags(cmd)
		if err != nil {
			return nil, err
		}

		adminOpts = append(adminOpts, adminclient.WithTLS(kwildTLSCertFile, clientTLSKeyFile, clientTLSCertFile))
	}

	if pass, err := cmd.Flags().GetString("pass"); err != nil {
		return nil, err
	} else if pass != "" {
		adminOpts = append(adminOpts, adminclient.WithPass(pass))
	}

	return adminclient.NewClient(ctx, rpcServer, adminOpts...)
}

// getTLSFlags returns the TLS flags from the given command.
func getTLSFlags(cmd *cobra.Command) (kwildTLSCertFile, clientTLSKeyFile, clientTLSCertFile string, err error) {
	kwildTLSCertFile, err = cmd.Flags().GetString("authrpc-cert")
	if err != nil {
		return "", "", "", err
	}

	clientTLSKeyFile, err = cmd.Flags().GetString("tlskey")
	if err != nil {
		return "", "", "", err
	}

	clientTLSCertFile, err = cmd.Flags().GetString("tlscert")
	if err != nil {
		return "", "", "", err
	}

	cert := nodeCert{
		KwildTLSCertFile:  kwildTLSCertFile,
		ClientTLSKeyFile:  clientTLSKeyFile,
		ClientTLSCertFile: clientTLSCertFile,
	}

	rootDir, err := bind.RootDir(cmd)
	if err != nil {
		return "", "", "", err
	}

	return cert.tlsFiles(rootDir)
}

// nodeCert is the struct that holds the TLS certificate and key files for
// kwil admin commands to use when connecting to the remote node.
type nodeCert struct {
	KwildTLSCertFile  string
	ClientTLSKeyFile  string // default: auth.key
	ClientTLSCertFile string // default: auth.cert
}

// tlsFiles loads the remote node's TLS certificate, which the client uses to
// authenticate the server during the connection handshake, and our TLS key
// pair, which allows the server to authenticate the client. The server's TLS
// certificate would be obtained from the node machine and specified with the
// --authrpc-cert flag, or this will search for it in known paths. The client key
// pair (ours) should first be generated with the `node gen-auth-key` command.
func (nc *nodeCert) tlsFiles(rootDir string) (nodeCert, ourKey, ourCert string, err error) {
	// Look for kwild's TLS certificate in:
	//  1. any path provided via --authrpc-cert
	//  2. ~/.kwild/admin.cert
	nodeCert = nc.KwildTLSCertFile // --authrpc-cert
	if nodeCert != "" {
		nodeCert = fullPath(nodeCert, rootDir)
	} else {
		nodeCert = fullPath(config.AdminServerCertName, rootDir) // ~/.kwild/admin.cert
	}
	if nodeCert == "" || !fileExists(nodeCert) {
		err = fmt.Errorf("kwild cert file not found, checked %v", nodeCert)
		return
	}
	ourKey, ourCert = fullPath(nc.ClientTLSKeyFile, rootDir), fullPath(nc.ClientTLSCertFile, rootDir)
	if ourKey == "" || ourCert == "" {
		err = errors.New("our TLS key/cert not found")
		return // leave the existence check until we load the files
	}

	return
}

// fullPath gets the full path to a file, searching in the following order:
//  1. the path itself, if it is absolute
//  2. the current directory
//  3. provided root directory
func fullPath(path, rootDir string) string {
	// If an absolute path is specified, do nothing.
	if filepath.IsAbs(path) {
		return path
	}

	// First check relative to the current directory.
	fullPath, err := filepath.Abs(path)
	if err != nil {
		return ""
	}
	if fileExists(fullPath) {
		return fullPath
	}

	// Check for the file name in root dir
	fullPath = filepath.Join(rootDir, path)
	if fileExists(fullPath) {
		return fullPath
	}

	return ""
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
