package rpc

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/trufnetwork/kwil-db/app/shared/bind"
	"github.com/trufnetwork/kwil-db/app/shared/display"
	"github.com/trufnetwork/kwil-db/core/rpc/transport"
)

var (
	genAuthKeyLong = `The ` + "`gen-auth-key`" + `command generates a new key pair for use with an authenticated admin RPC service.
	
The key pair is generated and stored in the node's configuration directory, in the files ` + "`adminclient.key`" + ` and ` + "`adminclient.cert`" + `. The key pair is used to authenticate the admin tool to the node.`
	genAuthKeyExample = `# Generate a new TLS key pair to talk to the node
kwild admin gen-auth-key
# kwild admin commands uses adminclient.{key,cert}, while kwild uses clients.pem`
)

func genAuthKeyCmd() *cobra.Command {
	var keyFile, certFile string

	cmd := &cobra.Command{
		Use:     "gen-auth-key",
		Short:   "Generate a new key pair for use with an authenticated admin RPC service.",
		Long:    genAuthKeyLong,
		Example: genAuthKeyExample,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rootDir, _ := bind.RootDir(cmd)

			if !filepath.IsAbs(keyFile) {
				keyFile = filepath.Join(rootDir, keyFile)
			}
			if fileExists(keyFile) {
				return display.PrintErr(cmd, fmt.Errorf("key file exists: %v", keyFile))
			}
			if err := os.MkdirAll(filepath.Dir(keyFile), 0755); err != nil {
				return display.PrintErr(cmd, fmt.Errorf("failed to create key file dir: %v", err))
			}

			if !filepath.IsAbs(certFile) {
				certFile = filepath.Join(rootDir, certFile)
			}
			if fileExists(certFile) {
				return display.PrintErr(cmd, fmt.Errorf("cert file exists: %v", certFile))
			}
			if err := os.MkdirAll(filepath.Dir(certFile), 0755); err != nil {
				return display.PrintErr(cmd, fmt.Errorf("failed to create key file dir: %v", err))
			}

			err := transport.GenTLSKeyPair(certFile, keyFile, "local kwild CA", nil)
			if err != nil {
				return display.PrintErr(cmd, fmt.Errorf("failed to generate TLS key pair: %v", err))
			}

			display.PrintCmd(cmd, display.RespString(fmt.Sprintf("TLS key pair generated in %v and %v\n", keyFile, certFile)))

			certText, err := os.ReadFile(certFile + "x")
			if err != nil {
				return display.PrintErr(cmd, fmt.Errorf("failed to read cert file: %v", err))
			}
			return display.PrintErr(cmd, appendToFile(filepath.Join(rootDir, "clients.pem"), certText))
		},
	}

	cmd.Flags().StringVar(&keyFile, "tlskey", "adminclient.key", "output path for the new client key file")
	cmd.Flags().StringVar(&certFile, "tlscert", "adminclient.cert", "output path for the new client certificate")

	return cmd
}

func appendToFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}
