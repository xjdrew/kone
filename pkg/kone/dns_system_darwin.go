package kone

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

func SupportsSystemDNS() bool { return darwinSystemDNSAcceptance }

func darwinSCRead(ctx context.Context, script string) ([]byte, error) {
	command := exec.CommandContext(ctx, "/usr/sbin/scutil")
	command.Stdin = strings.NewReader(script)
	command.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	command.WaitDelay = time.Second
	var output, diagnostics dnsLimitedOutput
	command.Stdout, command.Stderr = &output, &diagnostics
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("read SystemConfiguration: %w", err)
	}
	return output.Bytes(), nil
}

func CheckSystemDNS(ctx context.Context, cfg DNSConfig) error {
	if !cfg.System {
		return nil
	}
	if !SupportsSystemDNS() {
		return errors.New("dns.system macOS support awaits native acceptance")
	}
	servers := append([]string(nil), cfg.Servers...)
	for _, rule := range cfg.Rules {
		servers = append(servers, rule.Servers...)
	}
	if len(cfg.Servers) == 0 {
		observed, err := readDNSSystemContext()
		if err != nil {
			return errors.New("cannot safely discover the original macOS resolver")
		}
		servers = append(servers, observed.DefaultServers...)
		for _, scope := range observed.Scopes {
			servers = append(servers, scope.Servers...)
		}
	}
	for _, server := range servers {
		address, err := normalizeDNSServer(server)
		if err != nil {
			continue
		}
		host, port, _ := net.SplitHostPort(address)
		if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() && port == strconv.Itoa(int(cfg.ListenPort)) {
			return errors.New("dns.system cannot use its own loopback DNS listener as an upstream")
		}
	}
	// This is read-only and deliberately works for the ordinary management user.
	// The separately authorized data-plane helper creates the actual session.
	_, err := darwinSCRead(ctx, "show State:/Network/Global/DNS\nquit\n")
	return err
}

func (n systemNetwork) ConfigureSystemDNS(ctx context.Context, device Device, core CoreConfig, cfg DNSConfig) (Cleanup, error) {
	cleanup, _, err := n.ConfigureSystemDNSLease(ctx, device, core, cfg)
	return cleanup, err
}

func (n systemNetwork) ConfigureSystemDNSLease(ctx context.Context, device Device, core CoreConfig, cfg DNSConfig) (Cleanup, <-chan error, error) {
	if !cfg.System {
		return nil, nil, nil
	}
	if err := CheckSystemDNS(ctx, cfg); err != nil {
		return nil, nil, err
	}
	owned, ok := device.(*singDevice)
	if !ok || owned == nil || isNilInterface(owned.Tun) {
		return nil, nil, errors.New("system DNS requires an exclusively owned live utun")
	}
	name := device.Name()
	link, err := net.InterfaceByName(name)
	if err != nil {
		return nil, nil, err
	}
	index := link.Index
	verify := func() error {
		actual, err := owned.Tun.Name()
		if err != nil || actual != name {
			return errors.New("owned DNS utun identity changed")
		}
		current, err := net.InterfaceByName(name)
		if err != nil || current.Index != index {
			return errors.New("owned DNS utun was removed or replaced")
		}
		return nil
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, nil, err
	}
	encoded := hex.EncodeToString(random[:])
	id := encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
	// macOS utun is point-to-point: KONE's DNS socket is wildcard-bound and is
	// reached on loopback, rather than routing a DNS query back into the tunnel.
	cleanup, failures, err := configureScopedDNS(ctx, newDarwinScopedDNSHooks(), id, name, netip.MustParseAddr("127.0.0.1"), cfg.ListenPort, verify)
	wanted := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(cfg.ListenPort)))
	if cleanup != nil {
		releaseSession := cleanup
		var once sync.Once
		var restoreErr error
		cleanup = func(ctx context.Context) error {
			once.Do(func() {
				restoreErr = releaseSession(ctx)
				if restoreErr != nil {
					return
				}
				for {
					data, err := readDNSCommand(ctx, "/usr/sbin/scutil", "--dns")
					if err == nil {
						observed, err := parseDarwinDNSContext(data)
						if err == nil && !containsDNSValue(observed.DefaultServers, wanted) {
							return
						}
					}
					select {
					case <-ctx.Done():
						restoreErr = errors.New("system resolver restoration was not confirmed")
						return
					case <-time.After(25 * time.Millisecond):
					}
				}
			})
			return restoreErr
		}
	}
	if err != nil {
		return cleanup, failures, err
	}
	selection, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		data, err := readDNSCommand(selection, "/usr/sbin/scutil", "--dns")
		if err == nil {
			observed, err := parseDarwinDNSContext(data)
			if err == nil && containsDNSValue(observed.DefaultServers, wanted) {
				return cleanup, failures, nil
			}
		}
		select {
		case <-selection.Done():
			return cleanup, failures, errors.New("owned DNS key was not selected by the system resolver")
		case failure, open := <-failures:
			if !open || failure == nil {
				failure = errors.New("owned DNS session ended before system selection")
			}
			return cleanup, failures, failure
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func newDarwinScopedDNSHooks() scopedDNSHooks {
	return scopedDNSHooks{
		read: func(ctx context.Context, key string) ([]byte, error) {
			return darwinSCRead(ctx, "show "+key+"\nquit\n")
		},
		launch: func(script string) (scopedDNSProcess, error) {
			command := exec.Command("/usr/sbin/scutil")
			command.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
			command.WaitDelay = time.Second
			input, err := command.StdinPipe()
			if err != nil {
				return scopedDNSProcess{}, err
			}
			// Successful commands are silent; drain a bounded transcript so a stuck
			// reader cannot keep the session alive after the owning process exits.
			command.Stdout, command.Stderr = &dnsLimitedOutput{}, &dnsLimitedOutput{}
			if err := command.Start(); err != nil {
				input.Close()
				return scopedDNSProcess{}, err
			}
			process := scopedDNSProcess{input: input, wait: command.Wait, kill: command.Process.Kill}
			if _, err := input.Write([]byte(script)); err != nil {
				input.Close()
				_ = command.Process.Kill()
				_ = command.Wait()
				return scopedDNSProcess{}, errors.New("cannot initialize owned DNS session")
			}
			return process, nil
		},
	}
}
