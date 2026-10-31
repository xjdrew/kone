package kone

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// A temporary dynamic-store key belongs to the scutil session. Closing only that
// session delegates removal to configd's owner check; never issue a blind remove.
type scopedDNSProcess struct {
	input io.WriteCloser
	wait  func() error
	kill  func() error
}

type scopedDNSProfile map[string][]string

type scopedDNSHooks struct {
	read   func(context.Context, string) ([]byte, error)
	launch func(string) (scopedDNSProcess, error)
}

var scopedDNSIdentifier = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var scopedDNSInterface = regexp.MustCompile(`^utun[0-9]{1,8}$`)

func scopedDNSScript(id, device string, address netip.Addr, port uint16) (string, string, scopedDNSProfile, error) {
	if !scopedDNSIdentifier.MatchString(id) || !scopedDNSInterface.MatchString(device) || !address.Is4() || port == 0 {
		return "", "", nil, errors.New("invalid owned DNS session parameters")
	}
	key := "State:/Network/Service/" + id + "/DNS"
	profile := scopedDNSProfile{"__KONEOwner": {id}, "__KONEInterface": {device}, "ServerAddresses": {address.String()}, "ServerPort": {strconv.Itoa(int(port))}, "SearchOrder": {"1"}, "SupplementalMatchDomains": {""}}
	// SearchOrder is a scalar CFNumber. An array of numeric strings would not be
	// accepted as SupplementalMatchOrders. Empty match domain means default only;
	// more-specific native VPN/split scopes retain their own longest match.
	script := "open\nd.init\nd.add __KONEOwner " + id + "\nd.add __KONEInterface " + device +
		"\nd.add ServerAddresses * " + address.String() + "\nd.add ServerPort # " + strconv.Itoa(int(port)) +
		"\nd.add SearchOrder # 1\nd.add SupplementalMatchDomains * \"\"\nadd " + key + " temporary\n"
	return key, script, profile, nil
}

func parseScopedDNSProfile(data []byte) (scopedDNSProfile, bool, error) {
	if len(data) > 65536 {
		return nil, false, errors.New("owned DNS profile exceeds limit")
	}
	if strings.TrimSpace(string(data)) == "No such key" {
		return nil, false, nil
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 1024), 4096)
	profile := scopedDNSProfile{}
	started, finished, array := false, false, ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if !started {
			if line != "<dictionary> {" {
				return nil, false, errors.New("unexpected owned DNS profile")
			}
			started = true
			continue
		}
		if finished {
			return nil, false, errors.New("extra owned DNS profile data")
		}
		if line == "}" {
			if array != "" {
				array = ""
			} else {
				finished = true
			}
			continue
		}
		key, value, found := strings.Cut(line, ":")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !found || key == "" {
			return nil, false, errors.New("invalid owned DNS property")
		}
		if array != "" {
			if key != strconv.Itoa(len(profile[array])) || len(profile[array]) >= 16 {
				return nil, false, errors.New("invalid owned DNS array")
			}
			profile[array] = append(profile[array], value)
			continue
		}
		if _, duplicate := profile[key]; duplicate || len(profile) >= 16 {
			return nil, false, errors.New("duplicate or excessive owned DNS properties")
		}
		if value == "<array> {" {
			array = key
			profile[key] = []string{}
		} else {
			profile[key] = []string{value}
		}
	}
	if scanner.Err() != nil || !finished || array != "" {
		return nil, false, errors.New("incomplete owned DNS profile")
	}
	return profile, true, nil
}

func configureScopedDNS(ctx context.Context, hooks scopedDNSHooks, id, device string, address netip.Addr, port uint16, verifyOwned func() error) (Cleanup, <-chan error, error) {
	key, script, expected, err := scopedDNSScript(id, device, address, port)
	if err != nil {
		return nil, nil, err
	}
	if err := verifyOwned(); err != nil {
		return nil, nil, err
	}
	read := func(ctx context.Context) (scopedDNSProfile, bool, error) {
		data, err := hooks.read(ctx, key)
		if err != nil {
			return nil, false, err
		}
		return parseScopedDNSProfile(data)
	}
	if _, exists, err := read(ctx); err != nil || exists {
		if err == nil {
			err = errors.New("owned DNS key already exists; refusing to replace it")
		}
		return nil, nil, err
	}
	process, err := hooks.launch(script)
	if err != nil {
		return nil, nil, err
	}
	done, failures := make(chan struct{}), make(chan error, 1)
	monitorCtx, cancelMonitor := context.WithCancel(ctx)
	monitorDone := make(chan struct{})
	monitorStarted := false
	defer func() {
		if !monitorStarted {
			close(monitorDone)
		}
	}()
	var stopping atomic.Bool
	var faultOnce sync.Once
	report := func(err error) {
		faultOnce.Do(func() {
			if err != nil {
				failures <- err
			}
			close(failures)
		})
	}
	go func() {
		err := process.wait()
		close(done)
		if !stopping.Load() {
			if err == nil {
				err = errors.New("session stopped unexpectedly")
			}
			report(fmt.Errorf("owned system DNS session: %w", err))
		} else {
			report(nil)
		}
	}()
	var once sync.Once
	var cleanupErr error
	cleanup := func(ctx context.Context) error {
		once.Do(func() {
			stopping.Store(true)
			cancelMonitor()
			_ = process.input.Close()
			select {
			case <-done:
			case <-ctx.Done():
				_ = process.kill() // only the exact subprocess created above
				select {
				case <-done:
				case <-time.After(time.Second):
					cleanupErr = errors.New("owned DNS session termination was not confirmed")
					return
				}
			}
			select {
			case <-monitorDone:
			case <-ctx.Done():
				cleanupErr = errors.New("owned DNS lease monitor did not stop")
				return
			}
			for {
				profile, exists, err := read(ctx)
				if err != nil {
					cleanupErr = err
					return
				}
				if !exists {
					return
				}
				if !reflect.DeepEqual(profile, expected) {
					cleanupErr = errors.New("owned DNS key was replaced; external settings preserved")
					return
				}
				select {
				case <-ctx.Done():
					cleanupErr = errors.New("owned DNS key removal was not confirmed")
					return
				case <-time.After(25 * time.Millisecond):
				}
			}
		})
		return cleanupErr
	}
	setup, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		profile, exists, err := read(setup)
		if err != nil {
			return cleanup, failures, err
		}
		if exists {
			if !reflect.DeepEqual(profile, expected) {
				return cleanup, failures, errors.New("owned DNS session did not publish the expected profile")
			}
			if err := verifyOwned(); err != nil {
				return cleanup, failures, err
			}
			select {
			case <-done:
				return cleanup, failures, errors.New("owned DNS session exited during setup")
			default:
			}
			monitorStarted = true
			go func() {
				defer close(monitorDone)
				ticker := time.NewTicker(time.Second)
				defer ticker.Stop()
				for {
					select {
					case <-monitorCtx.Done():
						return
					case <-done:
						return
					case <-ticker.C:
						check, cancel := context.WithTimeout(monitorCtx, 2*time.Second)
						profile, exists, err := read(check)
						cancel()
						if stopping.Load() || monitorCtx.Err() != nil {
							return
						}
						if err == nil && (!exists || !reflect.DeepEqual(profile, expected)) {
							err = errors.New("owned system DNS profile changed")
						}
						if err == nil {
							err = verifyOwned()
						}
						if err != nil {
							report(err)
							return
						}
					}
				}
			}()
			return cleanup, failures, nil
		}
		select {
		case <-setup.Done():
			return cleanup, failures, errors.New("owned DNS session did not become ready")
		case <-done:
			return cleanup, failures, errors.New("owned DNS session exited during setup")
		case <-time.After(25 * time.Millisecond):
		}
	}
}
