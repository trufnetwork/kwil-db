package node

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"slices"
	"strconv"

	"github.com/trufnetwork/kwil-db/config"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/node/pg"
)

// dbOpener opens a sessioned database connection.  Note that in this function the
// dbName is not a Kwil dataset, but a database that can contain multiple
// datasets in different postgresql "schema".
type dbOpener func(ctx context.Context, dbName string, maxConns uint32) (*pg.DB, error)

func newDBOpener(host, port, user, pass string, filterSchemas func(string) bool) dbOpener {
	return func(ctx context.Context, dbName string, maxConns uint32) (*pg.DB, error) {
		cfg := &pg.DBConfig{
			PoolConfig: pg.PoolConfig{
				ConnConfig: pg.ConnConfig{
					Host:   host,
					Port:   port,
					User:   user,
					Pass:   pass,
					DBName: dbName,
				},
				MaxConns: maxConns,
			},
			SchemaFilter: filterSchemas,
		}
		return pg.NewDB(ctx, cfg)
	}
}

// poolOpener opens a basic database connection pool.
type PoolOpener func(ctx context.Context, dbName string, maxConns uint32) (*pg.Pool, error)

func newPoolBOpener(host, port, user, pass string) PoolOpener {
	return func(ctx context.Context, dbName string, maxConns uint32) (*pg.Pool, error) {
		cfg := &pg.PoolConfig{
			ConnConfig: pg.ConnConfig{
				Host:   host,
				Port:   port,
				User:   user,
				Pass:   pass,
				DBName: dbName,
			},
			MaxConns: maxConns,
		}
		return pg.NewPool(ctx, cfg)
	}
}

type coreDependencies struct {
	rootDir    string
	cfg        *config.Config
	genesisCfg *config.GenesisConfig
	privKey    crypto.PrivateKey

	closers *closeFuncs // for clean close on failBuild

	adminKey *tls.Certificate
	autogen  bool

	logger           log.Logger
	dbOpener         dbOpener
	namespaceManager *namespaceManager
	poolOpener       PoolOpener
}

// closeFuncs holds a list of closers
// it is used to close all resources on shutdown
type closeFuncs struct {
	closers []func() error
	logger  log.Logger
}

func (c *closeFuncs) addCloser(f func() error, msg string) {
	// push to top of stack
	c.closers = slices.Insert(c.closers, 0, func() error {
		c.logger.Info(msg)
		return f()
	})
}

// closeAll closes all closers
func (c *closeFuncs) closeAll() error {
	var err error
	for _, closer := range c.closers {
		err = errors.Join(closer())
	}

	return err
}

// panicErr is the type given to panic from failBuild so that the wrapped error
// may be type-inspected.
type panicErr struct {
	err error
	msg string
}

func (pe panicErr) String() string {
	return pe.msg
}

func (pe panicErr) Error() string { // error interface
	return pe.msg
}

func (pe panicErr) Unwrap() error {
	return pe.err
}

// getPostgresMajorVersion retrieve the major version number of postgres client tools (e.g., psql or pg_dump)
func getPostgresMajorVersion(command string) (int, error) {
	cmd := exec.Command(command, "--version")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return -1, fmt.Errorf("failed to execute %s: %w", command, err)
	}

	major, _, err := getPGVersion(out.String())
	if err != nil {
		return -1, fmt.Errorf("failed to get version: %w", err)
	}

	return major, nil
}

// getPGVersion extracts the major and minor version numbers from the version output of a PostgreSQL client tool.
func getPGVersion(versionOutput string) (int, int, error) {
	// Expected output format:
	// Mac OS X: psql (PostgreSQL) 16.0
	// Linux: psql (PostgreSQL) 16.4 (Ubuntu 16.4-1.pgdg22.04+1)
	re := regexp.MustCompile(`\(PostgreSQL\) (\d+)\.(\d+)(?:\.(\d+))?`)
	matches := re.FindStringSubmatch(versionOutput)

	if len(matches) == 0 {
		return -1, -1, fmt.Errorf("could not find a valid version in output: %s", versionOutput)
	}

	// Extract major version number
	major, err := strconv.Atoi(matches[1])
	if err != nil {
		return -1, -1, fmt.Errorf("failed to parse major version: %w", err)
	}

	// Extract minor version number
	minor, err := strconv.Atoi(matches[2])
	if err != nil {
		return -1, -1, fmt.Errorf("failed to parse minor version: %w", err)
	}

	return major, minor, nil
}

const (
	PGVersion = 16
)

// checkVersion validates the version of a PostgreSQL client tool against the expected version.
func checkVersion(command string, version int) error {
	major, err := getPostgresMajorVersion(command)
	if err != nil {
		return err
	}

	if major != version {
		return fmt.Errorf("expected %s version %d.x, got %d.x", command, version, major)
	}

	return nil
}
