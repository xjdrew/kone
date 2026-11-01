package kone

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
)

//go:embed dns_system_windows.ps1
var windowsDNSWorkerScript string

func SupportsSystemDNS() bool { return true }

type windowsDNSParameters struct {
	Action      string
	ID          string
	DeviceName  string
	DeviceIndex int
	Address     string
	LUID        string
	Servers     []string
}

type windowsDNSResponse struct {
	OK      bool                     `json:"ok"`
	Error   string                   `json:"error"`
	Code    string                   `json:"code"`
	Stopped bool                     `json:"stopped"`
	Entries []SystemDNSRecoveryEntry `json:"entries"`
	Context json.RawMessage          `json:"context"`
}

func windowsDNSPublicError(code string) error {
	switch code {
	case "root_policy_conflict":
		return errors.New("Windows system DNS is blocked by an existing root NRPT rule; preserve or explicitly adjust its owner policy")
	case "domain_policy":
		return errors.New("Windows system DNS cannot preserve this domain or global NRPT security policy; keep system DNS disabled")
	case "encrypted_policy":
		return errors.New("Windows system DNS cannot downgrade required encrypted DNS; keep the existing encrypted resolver policy")
	case "lease_busy":
		return errors.New("another KONE instance or interrupted machine DNS lease owns system DNS; pause that instance or inspect recovery")
	case "changed":
		return errors.New("Windows DNS ownership or policy changed; external settings were preserved and recovery needs inspection")
	default:
		return errors.New("Windows system DNS could not be verified or restored; inspect local recovery status")
	}
}

func validWindowsDNSLeaseID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, value := range id {
		if !(value >= '0' && value <= '9' || value >= 'a' && value <= 'f') {
			return false
		}
	}
	return true
}

func windowsDNSCommand(params windowsDNSParameters) (*exec.Cmd, error) {
	data, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	script := "$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + base64.StdEncoding.EncodeToString(data) + "')) | ConvertFrom-Json;\nfunction KoneReadContext {\n" + windowsDNSContextScript + "\n}\n" + windowsDNSWorkerScript
	return windowsDNSPowerShell(script)
}

func windowsDNSPowerShell(script string) (*exec.Cmd, error) {
	// EncodedCommand otherwise expands the embedded script past Windows' 32K
	// command-line limit. A compressed constant script keeps even long adapter
	// names safely below it; neither script nor parameters touch a temporary file.
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, _ = writer.Write([]byte(script))
	if err := writer.Close(); err != nil {
		return nil, err
	}
	script = "$z=[IO.Compression.GzipStream]::new([IO.MemoryStream]::new([Convert]::FromBase64String('" + base64.StdEncoding.EncodeToString(compressed.Bytes()) + "')),[IO.Compression.CompressionMode]::Decompress); & ([scriptblock]::Create([IO.StreamReader]::new($z).ReadToEnd()))"
	words := utf16.Encode([]rune(script))
	encoded := make([]byte, len(words)*2)
	for index, word := range words {
		binary.LittleEndian.PutUint16(encoded[index*2:], word)
	}
	command := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(encoded))
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	command.WaitDelay = time.Second
	return command, nil
}

// All mutation happens in the worker holding the same named mutex. In
// particular, the parent cannot release ownership between Add's generated GUID
// and its durable acknowledgement. stdin EOF also restores a dead parent's lease.
type windowsDNSWorker interface {
	Read(context.Context) (windowsDNSResponse, error)
	Write(string) error
	Close()
}

type windowsDNSProcess struct {
	command *exec.Cmd
	input   io.WriteCloser
	output  chan windowsDNSResponse
	done    chan struct{}
	abort   chan struct{}
	once    sync.Once
}

func startWindowsDNSWorker(params windowsDNSParameters) (windowsDNSWorker, error) {
	command, err := windowsDNSCommand(params)
	if err != nil {
		return nil, err
	}
	return startWindowsDNSProcess(command)
}

func startWindowsDNSProcess(command *exec.Cmd) (windowsDNSWorker, error) {
	input, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := command.StdoutPipe()
	if err != nil {
		input.Close()
		return nil, err
	}
	// Cmdlet errors may include VPN namespaces. The worker emits bounded fixed
	// public errors instead; its stderr is deliberately never copied to logs.
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		input.Close()
		output.Close()
		return nil, err
	}
	process := &windowsDNSProcess{command: command, input: input, output: make(chan windowsDNSResponse, 4), done: make(chan struct{}), abort: make(chan struct{})}
	go func() {
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 4096), 65536)
		var protocolErr error
		for scanner.Scan() {
			var response windowsDNSResponse
			if json.Unmarshal(scanner.Bytes(), &response) != nil {
				protocolErr = errors.New("invalid Windows DNS worker response")
				break
			}
			select {
			case process.output <- response:
			case <-process.abort:
			}
		}
		if protocolErr != nil || scanner.Err() != nil {
			_ = command.Process.Kill()
		}
		_ = command.Wait()
		close(process.done)
	}()
	return process, nil
}

func (p *windowsDNSProcess) Read(ctx context.Context) (windowsDNSResponse, error) {
	select {
	case response := <-p.output:
		if response.Error != "" {
			return response, windowsDNSPublicError(response.Code)
		}
		return response, nil
	default:
	}
	select {
	case response := <-p.output:
		if response.Error != "" {
			return response, windowsDNSPublicError(response.Code)
		}
		return response, nil
	case <-ctx.Done():
		return windowsDNSResponse{}, ctx.Err()
	case <-p.done:
		// A final ACK can be buffered concurrently with process exit.
		select {
		case response := <-p.output:
			if response.Error != "" {
				return response, windowsDNSPublicError(response.Code)
			}
			return response, nil
		default:
		}
		return windowsDNSResponse{}, errors.New("Windows system DNS worker exited before acknowledgement")
	}
}

func (p *windowsDNSProcess) Write(command string) error {
	_, err := io.WriteString(p.input, command+"\n")
	return err
}

func (p *windowsDNSProcess) Close() {
	p.input.Close()
	select {
	case <-p.done:
		return
	case <-time.After(time.Second):
		// The durable pending journal remains if a wedged worker must be killed.
		_ = p.command.Process.Kill()
	}
	p.once.Do(func() { close(p.abort) })
}

func windowsDNSRequest(ctx context.Context, params windowsDNSParameters) (windowsDNSResponse, error) {
	worker, err := startWindowsDNSWorker(params)
	if err != nil {
		return windowsDNSResponse{}, err
	}
	defer worker.Close()
	return worker.Read(ctx)
}

func CheckSystemDNS(ctx context.Context, cfg DNSConfig) error {
	return checkWindowsSystemDNS(ctx, cfg, windowsDNSRequest)
}

func checkWindowsSystemDNS(ctx context.Context, cfg DNSConfig, request func(context.Context, windowsDNSParameters) (windowsDNSResponse, error)) error {
	if !cfg.System {
		return nil
	}
	if cfg.ListenPort != 53 {
		return errors.New("Windows system DNS requires dns.listen-port = 53")
	}
	response, err := request(ctx, windowsDNSParameters{Action: "check"})
	if err != nil {
		return err
	}
	if !response.OK {
		return errors.New("Windows system DNS preflight was not acknowledged")
	}
	return nil
}

func (n systemNetwork) ConfigureSystemDNS(ctx context.Context, device Device, core CoreConfig, cfg DNSConfig) (Cleanup, error) {
	cleanup, _, err := n.ConfigureSystemDNSLease(ctx, device, core, cfg)
	return cleanup, err
}

func (n systemNetwork) ConfigureSystemDNSLease(ctx context.Context, device Device, core CoreConfig, cfg DNSConfig) (Cleanup, <-chan error, error) {
	if !cfg.System {
		return nil, nil, nil
	}
	if cfg.ListenPort != 53 {
		return nil, nil, errors.New("Windows system DNS requires dns.listen-port = 53")
	}
	owned, ok := device.(*singDevice)
	if !ok || owned == nil || isNilInterface(owned.Tun) {
		return nil, nil, errors.New("system DNS requires an exclusively owned live Wintun")
	}
	name, err := owned.Tun.Name()
	if err != nil || name != device.Name() {
		return nil, nil, errors.New("owned DNS adapter identity changed")
	}
	link, err := net.InterfaceByName(name)
	if err != nil {
		return nil, nil, err
	}
	native, ok := owned.Tun.(interface{ LUID() uint64 })
	if !ok || native.LUID() == 0 {
		return nil, nil, errors.New("owned Wintun handle identity is unavailable")
	}
	luid := strconv.FormatUint(native.LUID(), 10)
	network, err := netip.ParsePrefix(core.Network)
	if err != nil || !network.Addr().Is4() {
		return nil, nil, errors.New("system DNS requires the owned IPv4 DNS listener")
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, nil, err
	}
	return configureWindowsDNSLease(ctx, windowsDNSParameters{Action: "lease", ID: hex.EncodeToString(token[:]), DeviceName: name, DeviceIndex: link.Index, Address: network.Addr().String(), LUID: luid}, startWindowsDNSWorker, time.Second)
}

func configureWindowsDNSLease(ctx context.Context, params windowsDNSParameters, start func(windowsDNSParameters) (windowsDNSWorker, error), interval time.Duration) (Cleanup, <-chan error, error) {
	worker, err := start(params)
	if err != nil {
		return nil, nil, err
	}
	stop := make(chan context.Context, 1)
	done := make(chan struct{})
	failures := make(chan error, 1)
	var restoreErr error
	var once sync.Once
	cleanup := func(ctx context.Context) error {
		once.Do(func() { stop <- ctx })
		select {
		case <-done:
			return restoreErr
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	first, firstErr := worker.Read(ctx)
	if firstErr != nil || !first.OK {
		worker.Close() // EOF asks the worker to roll back any partial Add.
		return nil, nil, errors.Join(firstErr, errors.New("Windows system DNS startup was not acknowledged; inspect recovery if capture cannot restart"))
	}
	go func() {
		defer close(done)
		defer worker.Close()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		failed := false
		for {
			select {
			case cleanupContext := <-stop:
				if err := worker.Write("stop"); err != nil {
					restoreErr = fmt.Errorf("request Windows DNS restoration: %w", err)
					return
				}
				for {
					response, err := worker.Read(cleanupContext)
					if err != nil || !response.OK {
						restoreErr = errors.Join(err, errors.New("Windows DNS restoration was not confirmed; recovery is required"))
						return
					}
					if response.Stopped {
						return
					}
					// A verification that timed out before cleanup may still send
					// its ACK. Only the distinct stop ACK confirms restoration.
				}
			case <-ticker.C:
				if failed {
					continue
				}
				checkContext, cancel := context.WithTimeout(context.Background(), time.Second)
				err := worker.Write("verify")
				if err == nil {
					response, readErr := worker.Read(checkContext)
					err = readErr
					if err == nil && !response.OK {
						err = errors.New("Windows system DNS lease lost")
					}
				}
				cancel()
				if err != nil {
					failed = true
					failures <- fmt.Errorf("Windows system DNS lease lost: %w", err)
				}
			}
		}
	}()
	return cleanup, failures, nil
}

func InspectSystemDNSRecovery(ctx context.Context) ([]SystemDNSRecoveryEntry, error) {
	response, err := windowsDNSRequest(ctx, windowsDNSParameters{Action: "inspect"})
	if err != nil {
		return nil, err
	}
	return validateWindowsDNSRecovery(response.Entries)
}

func validateWindowsDNSRecovery(entries []SystemDNSRecoveryEntry) ([]SystemDNSRecoveryEntry, error) {
	if len(entries) > 16 {
		return nil, errors.New("Windows DNS recovery listing exceeds limit")
	}
	for _, entry := range entries {
		if !validWindowsDNSLeaseID(entry.ID) || entry.DeviceIndex <= 0 || len(entry.DeviceName) == 0 || len(entry.DeviceName) > 256 || strings.ContainsAny(entry.DeviceName, "\x00\r\n") {
			return nil, errors.New("invalid Windows DNS recovery identity")
		}
	}
	return entries, nil
}

func RecoverSystemDNS(ctx context.Context, id string) error {
	if !validWindowsDNSLeaseID(id) {
		return errors.New("invalid Windows DNS recovery lease ID")
	}
	response, err := windowsDNSRequest(ctx, windowsDNSParameters{Action: "recover", ID: id})
	if err != nil {
		return err
	}
	if !response.OK {
		return errors.New("Windows DNS recovery was not acknowledged")
	}
	return nil
}

func readWindowsOwnedDNSContext(ctx context.Context, servers []string) (DNSSystemContext, error) {
	response, err := windowsDNSRequest(ctx, windowsDNSParameters{Action: "context", Servers: servers})
	if err != nil {
		return DNSSystemContext{Source: "windows", RequireManual: true}, err
	}
	return parseWindowsDNSContext(response.Context)
}
