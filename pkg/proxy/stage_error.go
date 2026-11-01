package proxy

import (
	"errors"
	"net"
)

const (
	StageConnect   = "proxy_connect"
	StageDNS       = "proxy_dns"
	StageTLS       = "proxy_tls"
	StageAuth      = "proxy_auth"
	StageHandshake = "proxy_handshake"
	StageTransport = "proxy_transport"
)

// StageError adds protocol evidence without altering the underlying message,
// cancellation identity or certificate/network error chain.
type StageError struct {
	Stage string
	Err   error
}

func (e *StageError) Error() string {
	if e.Err == nil {
		return ""
	}
	return e.Err.Error()
}
func (e *StageError) Unwrap() error { return e.Err }
func (e *StageError) Timeout() bool {
	var value net.Error
	return errors.As(e.Err, &value) && value.Timeout()
}
func (e *StageError) Temporary() bool {
	var value interface{ Temporary() bool }
	return errors.As(e.Err, &value) && value.Temporary()
}
func ErrorStage(err error) string {
	var value *StageError
	if errors.As(err, &value) {
		return value.Stage
	}
	return ""
}
func atStage(stage string, err error) error {
	if err == nil {
		return nil
	}
	if ErrorStage(err) != "" {
		return err
	}
	return &StageError{Stage: stage, Err: err}
}

// TargetAcknowledged distinguishes a successful CONNECT/SOCKS reply from
// Shadowsocks AEAD transport setup, which has no target-connection success ACK.
func (p *Proxy) TargetAcknowledged() bool { return p != nil && p.Url != nil && p.Url.Scheme != "ss" }
