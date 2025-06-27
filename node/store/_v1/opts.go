package store

import (
	"fmt"

	"github.com/trufnetwork/kwil-db/core/log"
)

type options struct {
	logger log.Logger
}

type Option func(*options)

func WithLogger(logger log.Logger) Option {
	return func(o *options) {
		o.logger = logger
	}
}

// badgerLogger implements the badger.Logger interface.
type badgerLogger struct {
	log log.Logger
}

func (b *badgerLogger) Debugf(p0 string, p1 ...any) {
	b.log.Debug(fmt.Sprintf(p0, p1...))
}

func (b *badgerLogger) Errorf(p0 string, p1 ...any) {
	b.log.Error(fmt.Sprintf(p0, p1...))
}

func (b *badgerLogger) Infof(p0 string, p1 ...any) {
	b.log.Info(fmt.Sprintf(p0, p1...))
}

func (b *badgerLogger) Warningf(p0 string, p1 ...any) {
	b.log.Warn(fmt.Sprintf(p0, p1...))
}
