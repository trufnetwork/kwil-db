package bind

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/structs"
	"github.com/knadh/koanf/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/log"
	ktypes "github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/node/pg"
	"github.com/trufnetwork/kwil-db/node/types"
)

const (
	RootFlagName  = "root"
	rootShortName = "r"
)

// BindRootDirVar is used to bind the [RootFlagName] with a local command
// variable. The flag "root" does not have config file analog, so binds with
// local var, which is then available to all subcommands via RootDir(cmd).
func BindRootDirVar(cmd *cobra.Command, rootDir *string, defaultVal, desc string) {
	cmd.PersistentFlags().StringVarP(rootDir, RootFlagName, rootShortName,
		defaultVal, desc)
}

// BindRootDir is like [BindRootDirVar] but the bound variable is internal and
// returned as a *string, which may be ignored when using [RootDir].
func BindRootDir(cmd *cobra.Command, defaultVal, desc string) *string {
	// cmd.PersistentFlags().String("root-dir", defaultVal, desc) // legacy
	// cmd.PersistentFlags().MarkHidden("root-dir")
	return cmd.PersistentFlags().StringP(RootFlagName, rootShortName, defaultVal, desc)
}

// RootDir complements [BindRootDirVar] by returning the value of the root
// directory flag bound by [BindRootDirVar]. This is available for commands that
// do not have direct access to the local string pointer bound to the flag, such
// as subcommands.
func RootDir(cmd *cobra.Command) (string, error) {
	return cmd.Flags().GetString(RootFlagName)
}

// SetFlagsFromStruct is used to automate the creation of flags in the
// provided pflag set from a tagged struct. This uses the field tags:
// "toml" for the flag name, and "comment" for the help string. Any "_"
// characters in the "toml" tag are converted to "-" when defining the flag.
// This recurses into nested structs.
func SetFlagsFromStruct(fs *pflag.FlagSet, cfg interface{}) {
	SetFlagsFromStructTags(fs, cfg, "toml", "comment")
}

// SetFlagsFromStructTags is a more generalized version of [SetFlagsFromStruct]
// that allows setting the field tags used to get flag name and description.
func SetFlagsFromStructTags(fs *pflag.FlagSet, cfg interface{}, nameTag, descTag string) {
	fs.SortFlags = false

	val := reflect.ValueOf(cfg)
	typ := val.Type()
	if typ.Kind() == reflect.Ptr {
		val = val.Elem()
		typ = val.Type()
	}

	var setFlag func(field reflect.StructField, fieldVal reflect.Value, prefix string)
	setFlag = func(field reflect.StructField, fieldVal reflect.Value, prefix string) {
		// Get flag name from toml tag
		flagName := field.Tag.Get(nameTag)
		if flagName == "" {
			flagName = strings.ToLower(field.Name)
		}
		flagName, _, _ = strings.Cut(flagName, ",")
		flagName = strings.ReplaceAll(flagName, "_", "-")
		if prefix != "" {
			flagName = prefix + "." + flagName
		}

		// Get description from comment tag
		desc := field.Tag.Get(descTag)
		if desc == "" {
			desc = flagName // fallback to name if no comment
		}

		// Handle nested structs
		if field.Type.Kind() == reflect.Struct {
			for i := range field.Type.NumField() {
				setFlag(field.Type.Field(i), fieldVal.Field(i), flagName)
			}
			return
		}

		// first catch special types like log.Level and log.Format
		switch vt := fieldVal.Interface().(type) {
		case log.Level:
			fs.String(flagName, vt.String(), desc)
			return
		case log.Format:
			fs.String(flagName, string(vt), desc)
			return
		case time.Duration:
			fs.Duration(flagName, vt, desc)
			return
		case ktypes.Duration:
			fs.Duration(flagName, time.Duration(vt), desc)
			return
		case types.HexBytes:
			fs.BytesHex(flagName, vt, desc)
			return
		}
		// fallback to default flag set

		// Set flag based on field type
		switch field.Type.Kind() {
		case reflect.String:
			defaultVal := fieldVal.String()
			fs.String(flagName, defaultVal, desc)
		case reflect.Bool:
			defaultVal := fieldVal.Bool()
			fs.Bool(flagName, defaultVal, desc)
		case reflect.Int, reflect.Int64, reflect.Int16, reflect.Int32, reflect.Int8:
			defaultVal := fieldVal.Int()
			fs.Int64(flagName, defaultVal, desc)
		case reflect.Uint, reflect.Uint64, reflect.Uint16, reflect.Uint32, reflect.Uint8:
			defaultVal := fieldVal.Uint()
			fs.Uint64(flagName, defaultVal, desc)
		case reflect.Float64, reflect.Float32:
			defaultVal := fieldVal.Float()
			fs.Float64(flagName, defaultVal, desc)
		case reflect.Slice:
			switch sv := fieldVal.Interface().(type) {
			case []string:
				fs.StringSlice(flagName, sv, desc)

			// TODO: this will take some maint with different slice types
			// fs.IntSlice(), etc
			default:
				fmt.Printf("Unsupported slice type for flag: %T\n", sv)
			}
		case reflect.Map:
			switch mv := fieldVal.Interface().(type) {
			case map[string]string:
				fs.StringToString(flagName, mv, desc)
			}
		}
	}

	// Process all fields
	for i := range typ.NumField() {
		setFlag(typ.Field(i), val.Field(i), "")
	}
}

/*func SetNodeFlagsFromDefaultInKoanf(cmd *cobra.Command, k *koanf.Koanf) error {
	var cfg config.Config
	err := k.UnmarshalWithConf("", &cfg, koanf.UnmarshalConf{Tag: "koanf"})
	if err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}
	SetFlagsFromStruct(cmd.Flags(), &cfg)
	return nil
}*/

/* SetNodeFlags is superseded by SetFlagsFromStruct since the config struct
field tags and types provide everything needed to bind pflags without
maintaining and explicit list of flags as this did.

func SetNodeFlags(cmd *cobra.Command) {
	// TODO: do this automatically based on the node.Config struct, and the
	// tags, including `toml` and `comment`. This will probably involve
	// reflection unless the koanf instance that loaded the DefaultConfig
	// somehow can provide everything to us. For the default values given to the
	// flags, they can simply be the zero value for whatever type since we are
	// currently binding defaults via the struct from DefaultConfig, meaning the
	// flag defaults will never be used.

	fs := cmd.Flags()
	fs.SortFlags = false

	// top level (for now, may be common, node, etc.)
	fs.String("log-level", log.LevelInfo.String(), "log level")
	fs.String("log-format", string(log.FormatUnstructured), "log format")
	fs.BytesHex("privkey", nil, "private key to use for node")

	// [p2p]
	fs.StringSlice("p2p.bootnodes", nil, "bootnodes to connect to on startup")
	// fs.StringSlice("p2p.seeds", nil, "seeds to get peer addresses from (for pex only, not persistent peers)")
	fs.String("p2p.ip", "0.0.0.0", "ip to listen on for P2P connections")
	fs.Uint64("p2p.port", 6600, "port to listen on for P2P connections")

	fs.Bool("p2p.no-pex", false, "disable peer exchange") // default-false flag
	fs.Bool("p2p.pex", true, "enable peer exchange")      // default-true bool flag to match toml where it is best
	cmd.Flag("p2p.pex").Hidden = true                     // maybe remove if we keep default to enable pex

	// [consensus]
	fs.Duration("consensus.propose-timeout", 1000*time.Millisecond, "timeout for proposing a block (leader only)")
	fs.Uint64("consensus.max-block-size", 50_000_000, "maximum size of a block (in bytes)")
	fs.Uint64("consensus.max-txs-per-block", 20_000, "maximum number of transactions per block")

	...
}*/

// PreRunCmd is the function signature used with a cobra.Command.PreRunE or
// PersistentPreRunE. Use [ChainPreRuns] to apply multiple PreRunCmds.
type PreRunCmd func(*cobra.Command, []string) error

// ChainPreRuns chains a list of PreRunCmd functions into a single PreRunCmd.
// This can be used to set config sources and precedence by chaining
// [PreRunBindEnvAllSections], [PreRunBindEnvMatching], and [PreRunBindConfigFile].
// Use [BindDefaults] to initialize with defaults from a config struct.
func ChainPreRuns(preRuns ...PreRunCmd) PreRunCmd {
	return func(cmd *cobra.Command, args []string) error {
		for _, preRun := range preRuns {
			if err := preRun(cmd, args); err != nil {
				return err
			}
		}
		return nil
	}
}

// BindDefaultsTo loads the defaults from the provided config struct into a
// Koanf instance, using field names according to the given struct tag.
func BindDefaultsTo(cfg interface{}, tag string, k *koanf.Koanf) error {
	err := k.Load(structs.Provider(cfg, tag), nil)
	if err != nil {
		return fmt.Errorf("error loading config from struct: %v", err)
	}
	return nil
}

// The flags and config file load/merge currently standardizes to "_" instead of
// "-". With environment variables, where sections are delimited by "_", there
// is ambiguity as to whether to merge "KWIL_SECT_SOME_VALUE" with
// "sect.some.value" or "sect.some_value".

// PreRunBindEnvMatchingTo is to accomplish all of the following:
//
//	KWIL_SECTION_SUBSECTION_SOME_KEY => section.subsection.some-key
//	KWIL_SECTION_SUBSECTION_KEYNAME => section.subsection.keyname
//	KWIL_SECTION_SOME_KEY => section.some-key
//	KWIL_SECTION_KEYNAME => section.keyname
//
// For this to work correctly, a previously loaded default config struct
// (PreRunBindConfigFile) or pflags (PreRunBindFlags). If neither sources
// preceded env, they are loaded assuming every "_" is a section delimiter,
// which may be incorrect for multi-word keys like KWIL_SECTION_SOME_KEY.
func PreRunBindEnvMatchingTo(cmd *cobra.Command, args []string, prefix string, k *koanf.Koanf) error {
	kEnv := koanf.New(".")
	kEnv.Load(env.Provider(prefix, ".", func(s string) string {
		s, _ = strings.CutPrefix(s, prefix)
		return strings.ToLower(s) // no sections here
	}), nil)

	// Merge into k by mapping keys into env var format to find matches.
	// Matches will come from either a previously loaded default config struct
	// (PreRunBindConfigFile) or pflags (PreRunBindFlags). If neither sources
	// preceded env, they are loaded assuming every "_" is a section delimiter,
	// which may be incorrect for multi-word keys like KWIL_SECTION_SOME_KEY.
	envKeyMap := kEnv.All()         // flattened map - kEnv.Print()
	for key, val := range k.All() { // flattened keys+vals map
		envEquivKey := strings.NewReplacer(".", "_", "-", "_").Replace(key) // e.g. "section.sub.some-key" => "section_sub_some_key"
		if envVal, ok := envKeyMap[envEquivKey]; ok {
			Debugf("Merging env var: %s (%v) <= %s (%v)", key, val,
				strings.ToUpper(envEquivKey), envVal)
			k.Set(key, kEnv.Get(envEquivKey))
			delete(envKeyMap, envEquivKey)
		}
	}
	// Set the remaining unmatched env vars into k.
	for key, val := range envKeyMap {
		Debugf("Unmatched env var: %s", key)
		k.Set(strings.ReplaceAll(key, "_", "."), val)
	}
	return nil
}

// nolint WIP
func mergeWithKeyTransform(keyFn func(s string) string) func(src, dest map[string]interface{}) error {
	return func(src, dest map[string]interface{}) error {
		return mergeFunc(src, dest, keyFn)
	}
}

func mergeFunc(src, dest map[string]interface{}, keyFn func(s string) string) error {
	for key, srcVal := range src {
		// First transform the key to the desired format (e.g. remove underscores)
		key = keyFn(key)

		destVal, exists := dest[key]
		if !exists { // new
			dest[key] = srcVal
			continue
		}

		// attempt to merge, overwriting with srcVal or merging nested maps recursively
		srcMap, srcIsMap := srcVal.(map[string]interface{})
		destMap, destIsMap := destVal.(map[string]interface{})

		if srcIsMap != destIsMap {
			return errors.New("conflict: attempting to replace non-map with a map")
		}

		if srcIsMap { // both are maps
			return mergeFunc(srcMap, destMap, keyFn)
		}

		// Replace dest's non-map value with src's non-map value
		dest[key] = srcVal
	}
	return nil
}

// BindPostgresFlags binds top-level flags to connect to a postgres database.
// The provided config is used as defaults for the flags.
func BindPostgresFlags(cmd *cobra.Command, dbCfg *config.DBConfig) {
	cmd.Flags().String("dbname", dbCfg.DBName, "Name of the database in the PostgreSQL server")
	cmd.Flags().String("user", dbCfg.User, "User with administrative privileges on the database")
	cmd.Flags().String("password", dbCfg.Pass, "Password for the database user")
	cmd.Flags().String("host", dbCfg.Host, "Host of the database")
	cmd.Flags().String("port", dbCfg.Port, "Port of the database")
}

// GetPostgresFlags returns the postgres flags from the given command, using the
// given fallback config, which may be a combination of defaults and values from
// an existing config file.
func GetPostgresFlags(cmd *cobra.Command, dbCfg *config.DBConfig) (*pg.ConnConfig, error) {
	return MergePostgresFlags(&pg.ConnConfig{
		DBName: dbCfg.DBName,
		User:   dbCfg.User,
		Pass:   dbCfg.Pass,
		Host:   dbCfg.Host,
		Port:   dbCfg.Port,
	}, cmd)
}

// MergePostgresFlags merges the given connection config with the flags from the given command.
// It only sets the fields that are set in the flags.
func MergePostgresFlags(conf *pg.ConnConfig, cmd *cobra.Command) (*pg.ConnConfig, error) {
	var err error
	if cmd.Flags().Changed("dbname") {
		conf.DBName, err = cmd.Flags().GetString("dbname")
		if err != nil {
			return nil, err
		}
	}

	if cmd.Flags().Changed("user") {
		conf.User, err = cmd.Flags().GetString("user")
		if err != nil {
			return nil, err
		}
	}

	if cmd.Flags().Changed("password") {
		conf.Pass, err = cmd.Flags().GetString("password")
		if err != nil {
			return nil, err
		}
	}

	if cmd.Flags().Changed("host") {
		conf.Host, err = cmd.Flags().GetString("host")
		if err != nil {
			return nil, err
		}
	}

	if cmd.Flags().Changed("port") {
		conf.Port, err = cmd.Flags().GetString("port")
		if err != nil {
			return nil, err
		}
	}

	return conf, nil
}
