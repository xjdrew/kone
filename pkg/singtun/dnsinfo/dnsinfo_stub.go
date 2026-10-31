//go:build !darwin || !cgo

package dnsinfo

import "github.com/sagernet/sing/common/logger"

func Copy() *Configuration {
	return nil
}

type Watcher struct{}

func NewWatcher(callback func(), logger logger.Logger) (*Watcher, error) {
	return &Watcher{}, nil
}

func (w *Watcher) Close() error {
	return nil
}
