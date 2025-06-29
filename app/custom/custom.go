// package custom allows for the creation of a custom-branded CLI that packages
// together the kwil-cli and kwild CLIs.
package custom

import "github.com/trufnetwork/kwil-db/config"

// DefaultConfig is the function to return the default to all commands in this
// app package. This is a var so that a custom binary may override the defaults,
// which many commands obtain with this function.
var DefaultConfig = config.DefaultConfig

// binaryConfig configures the generated binary. It is able to control the binary names.
// It is primarily used for generating useful help commands that have proper names.
type binaryConfig struct {
	// ProjectName is the name of the project, which will be used in the help text.
	ProjectName string
	// RootCmd is the name of the root command.
	// If we are building kwild / kwil-cli, then RootCmd is empty.
	RootCmd string
	// NodeCmd is the name of the node command.
	NodeCmd string
	// ClientCmd is the name of the client command.
	ClientCmd string
}

var BinaryConfig = defaultBinaryConfig()

func (b *binaryConfig) NodeUsage() string {
	if b.RootCmd != "" {
		return b.RootCmd + " " + b.NodeCmd
	}
	return b.NodeCmd
}

func (b *binaryConfig) ClientUsage() string {
	if b.RootCmd != "" {
		return b.RootCmd + " " + b.ClientCmd
	}
	return b.ClientCmd
}

func defaultBinaryConfig() binaryConfig {
	return binaryConfig{
		ProjectName: "Kwil",
		NodeCmd:     "kwild",
		ClientCmd:   "kwil-cli",
	}
}
