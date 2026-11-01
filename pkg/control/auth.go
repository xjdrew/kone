package control

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

type Session struct {
	ID      string    `json:"id"`
	Role    string    `json:"role"`
	Created time.Time `json:"created_at"`
	Expires time.Time `json:"expires"`
	Remote  bool      `json:"remote"`
	csrf    string
}
type Pairing struct {
	Code    string    `json:"code"`
	Role    string    `json:"role"`
	Expires time.Time `json:"expires"`
}
type rateWindow struct {
	start time.Time
	count int
}

func (c *Controller) allowRequest(r *http.Request, login bool) bool {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	key := host
	period := time.Second
	limit := 120
	if login {
		key = "login:" + host
		period = time.Minute
		limit = 8
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for k, v := range c.requestRates {
		if now.Sub(v.start) > time.Minute {
			delete(c.requestRates, k)
		}
	}
	v := c.requestRates[key]
	if now.Sub(v.start) >= period {
		v = rateWindow{start: now}
	}
	if v.count >= limit {
		return false
	}
	if len(c.requestRates) >= 256 && v.count == 0 {
		return false
	}
	v.count++
	c.requestRates[key] = v
	return true
}
func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (c *Controller) newSession(role string, remote bool) (string, *Session) {
	token := randomToken()
	session := &Session{ID: randomID("session"), Role: role, Created: c.now(), Expires: c.now().Add(8 * time.Hour), Remote: remote, csrf: randomToken()}
	if remote {
		session.Expires = c.now().Add(time.Hour)
	}
	c.sessions[tokenHash(token)] = session
	return token, session
}
func (c *Controller) claim(token, code string, remote bool) (string, *Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for key, s := range c.sessions {
		if now.After(s.Expires) {
			delete(c.sessions, key)
		}
	}
	if len(c.sessions) >= 32 {
		return "", nil, errors.New("session limit reached; revoke an old session")
	}
	if !remote && token != "" && tokenHash(token) == tokenHash(c.bootstrap) && now.Before(c.bootstrapExpiry) && c.bootstrap != "" {
		c.bootstrap = ""
		t, s := c.newSession("admin", false)
		return t, s, nil
	}
	if pair, ok := c.pairs[code]; code != "" && ok && now.Before(pair.Expires) {
		delete(c.pairs, code)
		t, s := c.newSession(pair.Role, remote)
		return t, s, nil
	}
	return "", nil, errors.New("authorization expired or invalid")
}
func (c *Controller) pair(role string) (Pairing, error) {
	if role != "read" && role != "admin" {
		return Pairing{}, errors.New("role must be read or admin")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for code, p := range c.pairs {
		if c.now().After(p.Expires) {
			delete(c.pairs, code)
		}
	}
	if len(c.pairs) >= 4 {
		return Pairing{}, errors.New("too many pending pairing codes")
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return Pairing{}, err
	}
	code := ""
	for _, v := range b {
		code += fmt.Sprint(v % 10)
	}
	p := Pairing{Code: code, Role: role, Expires: c.now().Add(2 * time.Minute)}
	c.pairs[code] = p
	return p, nil
}

func (c *Controller) authorize(r *http.Request) (*Session, bool) {
	token := ""
	bearer := false
	if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		token = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		bearer = true
	} else if cookie, err := r.Cookie("kone_session"); err == nil {
		token = cookie.Value
	}
	if len(token) != 64 {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	session := c.sessions[tokenHash(token)]
	if session == nil || c.now().After(session.Expires) {
		return nil, false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && !bearer && r.Header.Get("X-CSRF-Token") != session.csrf {
		return nil, false
	}
	copy := *session
	return &copy, true
}

func localRemote(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	address, err := netip.ParseAddr(host)
	return err == nil && address.IsLoopback()
}

func (c *Controller) validOrigin(r *http.Request) bool {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		return false
	}
	host = strings.Trim(host, "[]")
	address, e := netip.ParseAddr(host)
	local := host == "localhost" || e == nil && address.IsLoopback()
	c.mu.Lock()
	listen := c.address
	lan := c.lan
	c.mu.Unlock()
	allowed := false
	if local && r.TLS == nil && localRemote(r) {
		if listen == "" {
			allowed = true
		} else {
			_, boundPort, _ := net.SplitHostPort(listen)
			allowed = port == boundPort
		}
	}
	if r.TLS != nil && lan != nil {
		allowed = r.Host == lan.address
	}
	if !allowed {
		return false
	}
	if strings.EqualFold(r.Header.Get("Sec-Fetch-Site"), "cross-site") {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		if err != nil || u.Host != r.Host || u.Scheme != scheme || u.User != nil {
			return false
		}
	}
	return true
}

func (c *Controller) revoke(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for hash, s := range c.sessions {
		if s.ID == id {
			delete(c.sessions, hash)
			return true
		}
	}
	return false
}
func (c *Controller) sessionList() []Session {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []Session{}
	for _, session := range c.sessions {
		if c.now().Before(session.Expires) {
			out = append(out, *session)
		}
	}
	return out
}
