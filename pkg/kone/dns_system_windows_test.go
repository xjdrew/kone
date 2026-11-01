package kone

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/stretchr/testify/require"
)

func TestWindowsDNSCommandEncodesBoundedData(t *testing.T) {
	name := "adapter ' ; $(throw 'must remain data') " + strings.Repeat("x", 200)
	command, err := windowsDNSCommand(windowsDNSParameters{Action: "lease", DeviceName: name})
	require.NoError(t, err)
	require.Less(t, len(strings.Join(command.Args, " ")), 32700)
	require.True(t, command.SysProcAttr.HideWindow)
	raw, err := base64.StdEncoding.DecodeString(command.Args[len(command.Args)-1])
	require.NoError(t, err)
	words := make([]uint16, len(raw)/2)
	for i := range words {
		words[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	outer := string(utf16.Decode(words))
	_, encoded, found := strings.Cut(outer, "FromBase64String('")
	require.True(t, found)
	encoded, _, _ = strings.Cut(encoded, "')")
	compressed, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	require.NoError(t, err)
	inner, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.NoError(t, reader.Close())
	require.Contains(t, string(inner), "function ExactRule")
	require.NotContains(t, string(inner), name)
	require.Contains(t, string(inner), "FromBase64String('")
}

type fakeWindowsDNSWorker struct {
	mu        sync.Mutex
	responses chan windowsDNSResponse
	commands  chan string
	closed    bool
	writeErr  error
}

func (w *fakeWindowsDNSWorker) Read(ctx context.Context) (windowsDNSResponse, error) {
	select {
	case value := <-w.responses:
		if value.Error != "" {
			return value, errors.New(value.Error)
		}
		return value, nil
	case <-ctx.Done():
		return windowsDNSResponse{}, ctx.Err()
	}
}
func (w *fakeWindowsDNSWorker) Write(command string) error {
	w.mu.Lock()
	err := w.writeErr
	w.mu.Unlock()
	if err != nil {
		return err
	}
	w.commands <- command
	return nil
}
func (w *fakeWindowsDNSWorker) Close() { w.mu.Lock(); w.closed = true; w.mu.Unlock() }
func newFakeWindowsDNSWorker() *fakeWindowsDNSWorker {
	return &fakeWindowsDNSWorker{responses: make(chan windowsDNSResponse, 8), commands: make(chan string, 8)}
}
func (w *fakeWindowsDNSWorker) start(windowsDNSParameters) (windowsDNSWorker, error) { return w, nil }

func TestWindowsDNSLeaseLifecycle(t *testing.T) {
	worker := newFakeWindowsDNSWorker()
	worker.responses <- windowsDNSResponse{OK: true}
	cleanup, failures, err := configureWindowsDNSLease(context.Background(), windowsDNSParameters{}, worker.start, time.Millisecond)
	require.NoError(t, err)
	require.Equal(t, "verify", <-worker.commands)
	worker.responses <- windowsDNSResponse{Error: "owned rule changed"}
	select {
	case err := <-failures:
		require.ErrorContains(t, err, "owned rule changed")
	case <-time.After(time.Second):
		t.Fatal("lost NRPT ownership was not reported")
	}
	go func() {
		if <-worker.commands == "stop" {
			worker.responses <- windowsDNSResponse{OK: true, Stopped: true}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, cleanup(ctx))
	require.NoError(t, cleanup(ctx))
	worker.mu.Lock()
	require.True(t, worker.closed)
	worker.mu.Unlock()
}

func TestWindowsDNSLeaseFailures(t *testing.T) {
	t.Run("start", func(t *testing.T) {
		_, _, err := configureWindowsDNSLease(context.Background(), windowsDNSParameters{}, func(windowsDNSParameters) (windowsDNSWorker, error) { return nil, errors.New("spawn failed") }, time.Hour)
		require.ErrorContains(t, err, "spawn failed")
	})
	t.Run("startup acknowledgement", func(t *testing.T) {
		worker := newFakeWindowsDNSWorker()
		worker.responses <- windowsDNSResponse{Error: "pending rolled back"}
		cleanup, _, err := configureWindowsDNSLease(context.Background(), windowsDNSParameters{}, worker.start, time.Hour)
		require.Nil(t, cleanup)
		require.ErrorContains(t, err, "pending rolled back")
		require.True(t, worker.closed)
	})
	for _, failure := range []string{"write", "ack"} {
		t.Run(failure, func(t *testing.T) {
			worker := newFakeWindowsDNSWorker()
			worker.responses <- windowsDNSResponse{OK: true}
			cleanup, _, err := configureWindowsDNSLease(context.Background(), windowsDNSParameters{}, worker.start, time.Hour)
			require.NoError(t, err)
			if failure == "write" {
				worker.mu.Lock()
				worker.writeErr = errors.New("pipe closed")
				worker.mu.Unlock()
			} else {
				worker.responses <- windowsDNSResponse{Error: "restoration refused"}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			require.Error(t, cleanup(ctx))
		})
	}
}

func TestWindowsDNSLeaseCleanupIgnoresLateVerificationACK(t *testing.T) {
	worker := newFakeWindowsDNSWorker()
	worker.responses <- windowsDNSResponse{OK: true}
	cleanup, _, err := configureWindowsDNSLease(context.Background(), windowsDNSParameters{}, worker.start, time.Hour)
	require.NoError(t, err)
	worker.responses <- windowsDNSResponse{OK: true}
	worker.responses <- windowsDNSResponse{OK: true, Stopped: true}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, cleanup(ctx))
}

func TestWindowsDNSPreflightAndRecoveryValidation(t *testing.T) {
	calls := 0
	request := func(_ context.Context, params windowsDNSParameters) (windowsDNSResponse, error) {
		calls++
		require.Equal(t, "check", params.Action)
		return windowsDNSResponse{OK: true}, nil
	}
	require.NoError(t, checkWindowsSystemDNS(context.Background(), DNSConfig{}, request))
	require.Error(t, checkWindowsSystemDNS(context.Background(), DNSConfig{System: true, ListenPort: 5353}, request))
	require.Zero(t, calls)
	require.NoError(t, checkWindowsSystemDNS(context.Background(), DNSConfig{System: true, ListenPort: 53}, request))
	require.Equal(t, 1, calls)
	entry := SystemDNSRecoveryEntry{ID: strings.Repeat("a", 32), DeviceIndex: 42, DeviceName: "owned"}
	_, err := validateWindowsDNSRecovery([]SystemDNSRecoveryEntry{entry})
	require.NoError(t, err)
	for _, id := range []string{"", strings.Repeat("A", 32), "../" + strings.Repeat("a", 29), strings.Repeat("a", 33)} {
		require.False(t, validWindowsDNSLeaseID(id))
		require.Error(t, RecoverSystemDNS(context.Background(), id)) // Rejected before starting PowerShell.
	}
	_, err = validateWindowsDNSRecovery(make([]SystemDNSRecoveryEntry, 17))
	require.Error(t, err)
	entry.DeviceName = "bad\nname"
	_, err = validateWindowsDNSRecovery([]SystemDNSRecoveryEntry{entry})
	require.Error(t, err)
	_, _, err = (systemNetwork{}).ConfigureSystemDNSLease(context.Background(), nil, CoreConfig{}, DNSConfig{System: true, ListenPort: 53})
	require.ErrorContains(t, err, "live Wintun")
	_, _, err = (systemNetwork{}).ConfigureSystemDNSLease(context.Background(), nil, CoreConfig{}, DNSConfig{System: true, ListenPort: 5353})
	require.ErrorContains(t, err, "53")
	cleanup, failures, err := (systemNetwork{}).ConfigureSystemDNSLease(context.Background(), nil, CoreConfig{}, DNSConfig{})
	require.NoError(t, err)
	require.Nil(t, cleanup)
	require.Nil(t, failures)
	for _, code := range []string{"root_policy_conflict", "domain_policy", "encrypted_policy", "lease_busy", "changed", "unknown secret-value"} {
		err := windowsDNSPublicError(code)
		require.Error(t, err)
		require.NotContains(t, err.Error(), "secret-value")
	}
}

func TestWindowsDNSWorkerPipeProtocol(t *testing.T) {
	// These subprocesses only print JSON/read stdin. They never import the DNS
	// controller or invoke networking/registry commands on the developer host.
	for _, tc := range []struct {
		name, script string
		wantError    bool
	}{
		{"ack", `[Console]::Out.WriteLine('{"ok":true}'); $null=[Console]::In.ReadLine()`, false},
		{"public failure", `[Console]::Out.WriteLine('{"error":"fixed failure"}')`, true},
		{"invalid JSON", `[Console]::Out.WriteLine('not json')`, true},
		{"EOF", `exit 1`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			worker, err := startWindowsDNSProcess(exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", tc.script))
			require.NoError(t, err)
			defer worker.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			response, err := worker.Read(ctx)
			if tc.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.True(t, response.OK)
				require.NoError(t, worker.Write("stop"))
			}
		})
	}
}

func TestWindowsDNSPolicyOwnershipWithMockCmdlets(t *testing.T) {
	// Load function definitions only, replacing every called OS cmdlet and ledger
	// operation. This executes real PowerShell ownership/CAS logic without ever
	// reading or changing DNS, routes, adapters, a mutex or the registry.
	definitions, _, found := strings.Cut(windowsDNSWorkerScript, "$script:mutex = $null")
	require.True(t, found)
	script := definitions + `
function Assert($condition, $message) { if(-not $condition){ throw $message } }
$script:rules=@(); $script:removed=@(); $script:deleted=@()
function Get-DnsClientNrptRule { $script:rules }
function Remove-DnsClientNrptRule($Name, [switch]$Force) {
    $script:removed+=@($Name); $script:rules=@($script:rules|Where-Object {$_.Name -cne $Name})
}
function DeleteLedger($record) { $script:deleted+=@($record.ID) }
function Rule($record) { [pscustomobject]@{
Name='{f7893661-7a9c-48a4-a6ad-d798caeb6799}';Version=2;Namespace=@('.');NameServers=$record.Address;
DisplayName=(Tag $record);Comment=(Note $record);NameEncoding='Disable';
DirectAccessEnabled=$false;DnsSecEnabled=$false;DnsSecValidationRequired=$false;
DirectAccessQueryIPsecRequired=$false;DnsSecQueryIPsecRequired=$false;
IPsecCARestriction='';DirectAccessDnsServers='';DirectAccessProxyName='';
DirectAccessQueryIPsecEncryption='';DnsSecQueryIPsecEncryption='';DirectAccessProxyType=''
} }
$record=[pscustomobject]@{ID=('a'*32);GUID='a6381dc0-bab6-4821-88c3-e930f6f23771';LUID='123';Address='10.207.0.1';RuleName=''}
$r=Rule $record
Assert (ExactRule $r $record) 'Expected exact pending rule'
Assert (@(CandidateRules @($r) $record).Count -eq 1) 'Pending token did not recover generated name'
foreach($field in @('Comment','DisplayName','NameServers','NameEncoding','IPsecCARestriction','DirectAccessDnsServers',
    'DirectAccessProxyName','DirectAccessQueryIPsecEncryption','DnsSecQueryIPsecEncryption','DirectAccessProxyType')) {
    $changed=Rule $record; $changed.$field='outside change'
    Assert (-not (ExactRule $changed $record)) ('Changed field accepted: '+$field)
}
foreach($field in @('DirectAccessEnabled','DnsSecEnabled','DnsSecValidationRequired',
    'DirectAccessQueryIPsecRequired','DnsSecQueryIPsecRequired')) {
    $changed=Rule $record; $changed.$field=$true
    Assert (-not (ExactRule $changed $record)) ('Changed security accepted: '+$field)
}
$changed=Rule $record; $changed.Namespace=@('.','.private.invalid')
Assert (-not (ExactRule $changed $record)) 'Expanded namespaces accepted'
$record.RuleName='{2d8e8e22-9e34-4425-828c-3280d2e41b3f}'
Assert (-not (ExactRule $r $record)) 'Replaced rule identity accepted'
$record.RuleName=''
$script:rules=@($r)
Restore $record
Assert ($script:removed.Count -eq 1 -and $script:deleted.Count -eq 1) 'Pending cleanup failed'
$script:removed=@();$script:deleted=@()
$changed=Rule $record; $changed.Comment='outside change'; $script:rules=@($changed)
$refused=$false;try{Restore $record}catch{$refused=$true}
Assert ($refused -and $script:removed.Count -eq 0 -and $script:deleted.Count -eq 0) 'Externally changed rule was deleted'
$foreign=Rule $record;$foreign.Name='{b35b51bc-4dc5-4a64-99cd-643db65425ee}';$foreign.DisplayName='external';$foreign.Comment='external';$foreign.NameServers='192.0.2.1'
$script:rules=@($foreign)
$refused=$false;try{Restore $record}catch{$refused=$true}
Assert ($refused -and $script:removed.Count -eq 0) 'Unidentified pending root was erased'
$script:rules=@();Restore $record
Assert ($script:deleted.Count -eq 1) 'Absent pending rule did not clear ledger'
$script:removed=@();$script:deleted=@();$script:rules=@($r,$foreign)
Restore $record
Assert ($script:rules.Count -eq 1 -and $script:rules[0].Name -ceq $foreign.Name) 'Cleanup removed an external root'
# Preflight policy and reason codes, with every OS read replaced below.
function ReadLedger { @() }
function Get-Command($Name) { return $true }
function Test-Path($LiteralPath) { return ($script:doh -eq 3 -and $LiteralPath -ceq 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient') }
function Get-ItemProperty { [pscustomobject]@{DoHPolicy=3} }
$script:queryPolicy='Disable';$script:doh=0;$script:strictDoh=$false
function Get-DnsClientNrptGlobal { [pscustomobject]@{EnableDAForAllNetworks='Disable';QueryPolicy=$script:queryPolicy;SecureNameQueryFallback='Disable'} }
function Get-DnsClientNrptPolicy { $script:rules }
function Get-DnsClientServerAddress { [pscustomobject]@{ServerAddresses=@('192.0.2.53')} }
function Get-DnsClientDohServerAddress { [pscustomobject]@{ServerAddress='192.0.2.53';AutoUpgrade=$script:strictDoh;AllowFallbackToUdp=$false} }
$script:rules=@($foreign)
$refused=$false;try{PolicyAvailable}catch{$refused=$true}
Assert ($refused -and $script:reason -ceq 'root_policy_conflict') 'Root policy conflict reason missing'
$script:rules=@();$script:queryPolicy='QueryBoth'
$refused=$false;try{PolicyAvailable}catch{$refused=$true}
Assert ($refused -and $script:reason -ceq 'domain_policy') 'Custom query policy was downgraded'
$script:queryPolicy='Disable';$script:doh=3
$refused=$false;try{PolicyAvailable}catch{$refused=$true}
Assert ($refused -and $script:reason -ceq 'encrypted_policy') 'Required encrypted global DNS was downgraded'
$script:doh=0;$script:strictDoh=$true
$refused=$false;try{PolicyAvailable}catch{$refused=$true}
Assert ($refused -and $script:reason -ceq 'encrypted_policy') 'Per-server encrypted-only DNS was downgraded'
$script:strictDoh=$false
PolicyAvailable
Emit @{ok=$true}
`
	command, err := windowsDNSPowerShell(script)
	require.NoError(t, err)
	output, err := command.CombinedOutput()
	require.NoError(t, err, "%s", output)
	require.Contains(t, string(output), `"ok":true`)
}
