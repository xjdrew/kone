package tun

import (
	"errors"
	"syscall"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

func IsRecoverableReadError(err error) bool {
	return errors.Is(err, ErrTooManySegments) || E.IsMulti(err, syscall.EAGAIN, syscall.EINTR, syscall.ENOMEM, syscall.ENOBUFS)
}

type ReadRetry struct {
	delay time.Duration
}

func (r *ReadRetry) Wait(err error) {
	if errors.Is(err, ErrTooManySegments) {
		return
	}
	if r.delay == 0 {
		r.delay = 5 * time.Millisecond
	} else {
		r.delay = min(2*r.delay, time.Second)
	}
	time.Sleep(r.delay)
}

func (r *ReadRetry) Reset() {
	r.delay = 0
}
