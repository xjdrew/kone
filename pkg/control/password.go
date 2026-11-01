package control

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2id uses the RFC 9106 memory-constrained profile, with one lane to
// bound CPU use on gateways. See https://pkg.go.dev/golang.org/x/crypto/argon2.
const passwordMemory = 64 * 1024
const passwordIterations = 3

type passwordCredentials struct {
	Version int    `json:"version"`
	Salt    []byte `json:"salt"`
	Hash    []byte `json:"hash"`
	slots   chan struct{}
}

func (c *Controller) initAuthentication() error {
	c.credentials = &passwordCredentials{slots: make(chan struct{}, 2)}
	file, err := os.Open(filepath.Join(c.directory, "auth.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("cannot read management password; repair auth.json before restarting")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(data) > 4096 {
		return errors.New("management password file exceeds its size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(c.credentials) != nil || c.credentials.Version != 1 || len(c.credentials.Salt) != 16 || len(c.credentials.Hash) != 32 {
		return errors.New("management password file is invalid; preserve and repair auth.json")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("management password file has invalid framing")
	}
	return nil
}

func validPassword(password string) bool {
	return len(password) <= 128 && utf8.ValidString(password) && utf8.RuneCountInString(password) >= 8 && strings.TrimSpace(password) != ""
}

func passwordKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, passwordIterations, passwordMemory, 1, 32)
}

func (c *Controller) passwordConfigured() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.credentials != nil && len(c.credentials.Hash) != 0
}

func (c *Controller) authInformation(w http.ResponseWriter, r *http.Request) {
	configured := c.passwordConfigured()
	session, ok := c.authorize(r)
	setup := !configured && ok && session.Role == "setup" && !session.Remote && localRemote(r)
	info := map[string]any{"setup_required": !configured, "password_required": configured,
		"setup_authorized": setup, "authenticated": configured && ok && session.Role != "setup"}
	if setup {
		info["csrf_token"] = session.csrf
	} // Resume authorized setup after a page reload.
	writeJSON(w, 200, info)
}

func (c *Controller) setupPassword(w http.ResponseWriter, r *http.Request, session *Session) {
	if session.Role != "setup" || session.Remote || !localRemote(r) {
		apiError(w, 403, "setup_required", "Open the local tray entry to set the management password")
		return
	}
	var input struct {
		Password string `json:"password"`
		Confirm  string `json:"confirm_password"`
	}
	if readJSON(w, r, &input) != nil || !validPassword(input.Password) || input.Password != input.Confirm {
		apiError(w, 400, "password", "Use matching passwords of at least 8 characters and at most 128 UTF-8 bytes")
		return
	}
	if c.passwordConfigured() {
		apiError(w, 409, "password_configured", "Management password is already configured")
		return
	}
	select {
	case c.credentials.slots <- struct{}{}:
		defer func() { <-c.credentials.slots }()
	default:
		apiError(w, 429, "busy", "Password verification is busy; retry later")
		return
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		apiError(w, 500, "password", "Could not prepare the management password")
		return
	}
	credential := passwordCredentials{Version: 1, Salt: salt, Hash: passwordKey(input.Password, salt)}
	data, _ := json.Marshal(credential)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		apiError(w, 409, "stopped", "Management is stopped")
		return
	}
	if len(c.credentials.Hash) != 0 {
		c.mu.Unlock()
		apiError(w, 409, "password_configured", "Management password is already configured")
		return
	}
	err := atomicWrite(filepath.Join(c.directory, "auth.json"), data)
	if err != nil {
		c.mu.Unlock()
		apiError(w, 500, "password", "Could not save the management password")
		return
	}
	c.credentials.Version, c.credentials.Salt, c.credentials.Hash = credential.Version, credential.Salt, credential.Hash
	c.sessions = map[string]*Session{}
	c.pairs = map[string]Pairing{}
	c.bootstrap = ""
	token, owner := c.newSession("admin", false)
	c.mu.Unlock()
	writeSession(w, r, token, owner)
}

func (c *Controller) passwordSession(password string, remote bool) (string, *Session, error) {
	if !validPassword(password) {
		return "", nil, errors.New("invalid password")
	}
	c.mu.Lock()
	credential := *c.credentials
	c.mu.Unlock()
	if len(credential.Hash) != 32 {
		return "", nil, errors.New("set the management password from the local tray first")
	}
	select {
	case credential.slots <- struct{}{}:
		defer func() { <-credential.slots }()
	default:
		return "", nil, errors.New("password verification is busy; retry later")
	}
	key := passwordKey(password, credential.Salt)
	if subtle.ConstantTimeCompare(key, credential.Hash) != 1 {
		return "", nil, errors.New("invalid password")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for hash, session := range c.sessions {
		if !c.now().Before(session.Expires) {
			delete(c.sessions, hash)
		}
	}
	if c.closed || len(c.sessions) >= 32 {
		return "", nil, errors.New("session unavailable; revoke an old session or retry later")
	}
	token, session := c.newSession("admin", remote)
	return token, session, nil
}

func writeSession(w http.ResponseWriter, r *http.Request, token string, session *Session) {
	http.SetCookie(w, &http.Cookie{Name: "kone_session", Value: token, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: int(time.Until(session.Expires).Seconds())})
	writeJSON(w, 200, map[string]any{"role": session.Role, "session_id": session.ID, "csrf_token": session.csrf, "expires": session.Expires, "setup_required": session.Role == "setup"})
}

func (c *Controller) createSession(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Token       string `json:"token"`
		PairingCode string `json:"pairing_code"`
		Password    string `json:"password"`
	}
	if readJSON(w, r, &input) != nil {
		apiError(w, 400, "request", "Invalid authorization request")
		return
	}
	count := 0
	for _, value := range []string{input.Token, input.PairingCode, input.Password} {
		if value != "" {
			count++
		}
	}
	if count != 1 || len(input.Token) > 64 || len(input.PairingCode) > 16 || len(input.Password) > 128 {
		apiError(w, 400, "request", "Supply one password, local setup token or pairing code")
		return
	}
	var token string
	var session *Session
	var err error
	if input.Password != "" {
		token, session, err = c.passwordSession(input.Password, !localRemote(r))
	} else {
		token, session, err = c.claim(input.Token, input.PairingCode, !localRemote(r))
	}
	if err != nil {
		apiError(w, 401, "unauthorized", "Password or authorization is invalid; open the local tray entry for first-time setup")
		return
	}
	writeSession(w, r, token, session)
}
