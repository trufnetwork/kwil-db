package config

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	jsoncfg "github.com/knadh/koanf/parsers/json"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/posflag" // for spf13/pflag
	"github.com/knadh/koanf/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag" // with providers/posflag

	"github.com/trufnetwork/kwil-db/app/shared/bind"
	"github.com/trufnetwork/kwil-db/cmd/kwil-cli/helpers"
	"github.com/trufnetwork/kwil-db/core/crypto"
)

const (
	defaultConfigDirName  = ".kwil-cli"
	defaultConfigFileName = "config.json"

	configFileFlag      = "config"
	configFileFlagShort = "c"
)

var (
	// configFile default is set in init(), and bound to the --config flag in
	// BindConfigPath. It is global for PersistConfig/LoadPersistedConfig.
	configFile string

	cliCfg = DefaultKwilCliPersistedConfig()
)

func init() {
	dirname, err := os.UserHomeDir()
	if err != nil {
		dirname = os.TempDir()
	}

	configFile = filepath.Join(dirname, defaultConfigDirName, defaultConfigFileName)
}

var k = koanf.New(".")

func ActiveConfig() (*KwilCliConfig, error) {
	var cfg kwilCliPersistedConfig
	err := k.UnmarshalWithConf("", &cfg, koanf.UnmarshalConf{Tag: "json"})
	if err != nil {
		panic(fmt.Sprintf("failed to unmarshal config: %v", err))
	}
	return cfg.toKwilCliConfig()
}

// BindDefaults initializes the active configuration with the defaults set by
// DefaultKwilCliPersistedConfig.
func BindDefaults() error {
	return bind.BindDefaultsTo(cliCfg, "json", k)
}

// SetFlags defines flags for all fields of the default config set by
// DefaultKwilCliPersistedConfig.
func SetFlags(fs *pflag.FlagSet) {
	bind.SetFlagsFromStructTags(fs, cliCfg, "json", "comment")
}

// BindConfigPath defines the `--config` flag. Use [ConfigFilePath] to retrieve
// the value. The value of this flag informs [PreRunBindConfigFile].
func BindConfigPath(cmd *cobra.Command) {
	desc := "the path to the Kwil CLI persistent global settings file"
	cmd.PersistentFlags().StringVarP(&configFile, configFileFlag, configFileFlagShort,
		configFile, desc)
}

// ConfigFilePFlag returns the Flag for the --config flag. If the flag was not
// correctly bound with [BindConfigPath] first, it returns nil.
func ConfigFilePFlag(cmd *cobra.Command) *pflag.Flag {
	return cmd.Flags().Lookup(configFileFlag)
}

// ConfigFilePath returns the value bound to the --config flag. If you need to
// know if it was changed from the default or correctly bound, use [ConfigFilePFlag].
func ConfigFilePath() string {
	return configFile // bound to configFileFlag by pointer
}

// ConfigDir is the equivalent of filepath.Dir(ConfigFilePath()).
func ConfigDir() string {
	return filepath.Dir(configFile)
}

// PreRunBindConfigFile loads and merges settings from the JSON config file.
func PreRunBindConfigFile(cmd *cobra.Command, args []string) error {
	confFlag := ConfigFilePFlag(cmd)
	if confFlag == nil {
		return fmt.Errorf("--%s flag is not bound (missing BindConfigPath)", configFileFlag)
	}
	cfgPath := confFlag.Value.String()
	cfgPathSet := confFlag.Changed // if true, error if file not found

	cfgPath, err := helpers.ExpandPath(cfgPath)
	if err != nil {
		return err
	}

	// Load config from file
	confPath, _ := filepath.Abs(cfgPath)
	if err := k.Load(file.Provider(confPath), jsoncfg.Parser() /*, mergeFn*/); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("error loading config from %v: %w", confPath, err)
		}
		if cfgPathSet {
			return fmt.Errorf("specified config file at %v not found", confPath)
		}
		// Not an error, just no config file present at default location.
		bind.Debugf("No config file present at %v", confPath)
	}
	return nil
}

// PreRunBindFlags binds the current command's flags to the merged config. Use
// this with PersistentPreRunE in the root command to have it run for every
// command, or use with PreRunE for just the current command.
func PreRunBindFlags(cmd *cobra.Command, args []string) error {
	return PreRunBindFlagset(cmd.Flags(), args)
}

// PreRunBindFlagset is like [PreRunBindFlags] be used for a specific flag set.
func PreRunBindFlagset(flagSet *pflag.FlagSet, args []string) error {
	err := k.Load(posflag.ProviderWithFlag(flagSet, ".", nil, /* <- k if we want defaults from the flags' defaults*/
		func(f *pflag.Flag) (string, interface{}) {
			// if !f.Changed { Debugf("not changed %v", f.Name) }
			key := strings.ToLower(f.Name)
			val := posflag.FlagVal(flagSet, f)

			if f.Changed {
				// special case translations
				switch key {
				/*case "p2p.no-pex":
				newKey := "p2p.pex"
				if valB, ok := val.(bool); ok {
					Debugf("translating flag %s = %v => %s = %v", key, valB, newKey, !valB)
					val = !valB // negate
					key = newKey
				}
				*/
				}
			}

			return strings.ReplaceAll(key, "-", "_"), val
		}), nil /*no parser for flags*/ /*, mergeFn*/)
	if err != nil {
		return fmt.Errorf("error loading config: %v", err)
	}
	return nil
}

func PreRunPrintEffectiveConfig(cmd *cobra.Command, args []string) error {
	bind.Debugf("merged config map:\n%s\n", bind.LazyPrinter(func() string {
		return k.Sprint()
	}))
	return nil
}

func PreRunBindEnv(cmd *cobra.Command, args []string) error {
	return bind.PreRunBindEnvMatchingTo(cmd, args, "KWILCLI_", k)
}

type KwilCliConfig struct {
	PrivateKey *crypto.Secp256k1PrivateKey
	Provider   string
	ChainID    string
}

// Identity returns the account ID, or nil if no private key is set. These are
// the bytes of the ethereum address. UNUSED?
// func (c *KwilCliConfig) Identity() []byte {
// 	if c.PrivateKey == nil {
// 		return nil
// 	}
// 	signer := &auth.EthPersonalSigner{Key: *c.PrivateKey}
// 	return signer.CompactID()
// }

func (c *KwilCliConfig) ToPersistedConfig() *kwilCliPersistedConfig {
	var privKeyHex string
	if c.PrivateKey != nil {
		privKeyHex = hex.EncodeToString(c.PrivateKey.Bytes())
	}
	return &kwilCliPersistedConfig{
		PrivateKey: privKeyHex,
		Provider:   c.Provider,
		ChainID:    c.ChainID,
	}
}

func DefaultKwilCliPersistedConfig() *kwilCliPersistedConfig {
	return &kwilCliPersistedConfig{
		Provider: "http://127.0.0.1:8484",
	}
}

// kwilCliPersistedConfig is the config that is used to persist the config file
type kwilCliPersistedConfig struct {
	PrivateKey string `json:"private_key,omitempty" comment:"the private key of the wallet that will be used for signing"`
	Provider   string `json:"provider,omitempty" comment:"the Kwil provider RPC endpoint"`
	ChainID    string `json:"chain_id,omitempty" comment:"the expected/intended Kwil Chain ID"`
}

func (c *kwilCliPersistedConfig) toKwilCliConfig() (*KwilCliConfig, error) {
	kwilConfig := &KwilCliConfig{
		Provider: c.Provider,
		ChainID:  c.ChainID,
	}

	// NOTE: so non private_key required cmds could be run
	if c.PrivateKey == "" {
		return kwilConfig, nil
	}

	// we should complain if the private key is configured and invalid
	privKeyBts, err := hex.DecodeString(c.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	privateKey, err := crypto.UnmarshalSecp256k1PrivateKey(privKeyBts)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	kwilConfig.PrivateKey = privateKey

	return kwilConfig, nil
}

func PersistConfig(conf *KwilCliConfig) error {
	file, err := helpers.CreateOrOpenFile(configFile)
	if err != nil {
		return fmt.Errorf("failed to create or open config file: %w", err)
	}

	err = file.Truncate(0)
	if err != nil {
		return fmt.Errorf("failed to truncate config file: %w", err)
	}

	persistable := conf.ToPersistedConfig()
	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	err = enc.Encode(persistable)
	if err != nil {
		return fmt.Errorf("failed to write to config file: %w", err)
	}

	return nil
}

func LoadPersistedConfig() (*KwilCliConfig, error) {
	bts, err := helpers.ReadOrCreateFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create or open config file: %w", err)
	}

	if len(bts) == 0 {
		fmt.Printf("config file is empty, creating new one")
		return &KwilCliConfig{}, nil
	}

	var conf kwilCliPersistedConfig
	err = json.Unmarshal(bts, &conf)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config file: %w", err)
	}

	return conf.toKwilCliConfig()
}

/*func askAndDeleteConfig() {
	cfgPath := k.String(configFileFlag)
	if cfgPath == "" {
		fmt.Printf("Unable to retrieve config file path")
		return
	}

	askDelete := &prompt.Prompter{
		Label: fmt.Sprintf("Would you like to delete the corrupted config file at %s? (y/n) ", cfgPath),
	}

	response, err := askDelete.Run()
	if err != nil {
		fmt.Printf("Error reading response: %s\n", err)
		return
	}

	if response != "y" {
		fmt.Println("Not deleting config file.  Using default values and/or flags.")
		return
	}

	err = os.Remove(cfgPath)
	if err != nil {
		fmt.Printf("Error deleting config file: %s\n", err)
		return
	}
}*/
