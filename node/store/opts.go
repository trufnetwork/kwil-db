package store

import (
	"github.com/trufnetwork/kwil-db/core/log"
)

type options struct {
	logger   log.Logger
	compress bool
	// blockSize      int
	// blockCacheSize int
}

type Option func(*options)

func WithLogger(logger log.Logger) Option {
	return func(o *options) {
		o.logger = logger
	}
}

func WithCompression(compress bool) Option {
	return func(o *options) {
		o.compress = compress
	}
}

/*func WithBlockSize(size int) Option {
	return func(o *options) {
		o.blockSize = size
	}
}

func WithBlockCacheSize(size int) Option {
	return func(o *options) {
		o.blockCacheSize = size
	}
}*/

// badgerLogger implements the badger.Logger interface.
type badgerLogger struct {
	log log.Logger
}

func (b *badgerLogger) Debugf(msg string, args ...any) {
	b.log.Debugf(msg, args...)
}

func (b *badgerLogger) Errorf(msg string, args ...any) {
	b.log.Errorf(msg, args...)
}

func (b *badgerLogger) Infof(msg string, args ...any) {
	b.log.Infof(msg, args...)
}

func (b *badgerLogger) Warningf(msg string, args ...any) {
	b.log.Warnf(msg, args...)
}
