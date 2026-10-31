package kone

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"unicode/utf16"
)

// Encode both the script and its JSON parameters: adapter names and addresses
// are data, never PowerShell source. No process-global network state is used.
func (n systemNetwork) powershell(ctx context.Context, script string, params any) ([]byte, error) {
	data, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	script = "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); $p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + base64.StdEncoding.EncodeToString(data) + "')) | ConvertFrom-Json; " + script
	words := utf16.Encode([]rune(script))
	encoded := make([]byte, len(words)*2)
	for i, w := range words {
		binary.LittleEndian.PutUint16(encoded[i*2:], w)
	}
	return n.run(ctx, "powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(encoded))
}

type windowsSettings struct {
	Index, MTU, Metric    int
	AutomaticMetric, DHCP string
	DNS                   []string
	StaticDNS             bool
	Addresses             []struct {
		IPAddress    string
		PrefixLength int
	}
}

const readWindowsSettings = `
$a=Get-NetAdapter -Name ([System.Management.Automation.WildcardPattern]::Escape($p.Name));
$i=Get-NetIPInterface -InterfaceIndex $a.ifIndex -AddressFamily IPv4;
$dns=Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4;
$key='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\'+([guid]$a.InterfaceGuid).ToString('B');
$static=(Get-ItemProperty -LiteralPath $key).NameServer;
try { $addresses=@(Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction Stop) } catch { if($_.FullyQualifiedErrorId -notlike 'CmdletizationQuery_NotFound*'){throw}; $addresses=@() };
[pscustomobject]@{Index=[int]$a.ifIndex;MTU=[int]$i.NlMtu;Metric=[int]$i.InterfaceMetric;AutomaticMetric=$i.AutomaticMetric.ToString();DHCP=$i.Dhcp.ToString();DNS=@($dns.ServerAddresses);StaticDNS=![string]::IsNullOrWhiteSpace($static);Addresses=@($addresses | Select-Object IPAddress,PrefixLength)} | ConvertTo-Json -Depth 5 -Compress`

func (n systemNetwork) Configure(ctx context.Context, d Device, cfg CoreConfig) (Cleanup, error) {
	data, err := n.powershell(ctx, readWindowsSettings, map[string]any{"Name": d.Name()})
	if err != nil {
		return nil, err
	}
	var old windowsSettings
	if err := json.Unmarshal(data, &old); err != nil {
		return nil, fmt.Errorf("read interface snapshot: %w", err)
	}
	if old.Index <= 0 || old.MTU <= 0 || (old.DHCP != "Enabled" && old.DHCP != "Disabled") || (old.AutomaticMetric != "Enabled" && old.AutomaticMetric != "Disabled") {
		return nil, fmt.Errorf("invalid interface snapshot")
	}
	ip, subnet, _ := net.ParseCIDR(cfg.Network)
	prefix, _ := subnet.Mask.Size()
	for _, addr := range old.Addresses {
		if addr.IPAddress == ip.String() {
			return nil, fmt.Errorf("virtual address %s already exists on %s", ip, d.Name())
		}
	}
	var ipv6Snapshot *windowsIPv6Settings
	if cfg.IPv6Network != "" {
		settings, err := n.readIPv6Settings(ctx, d, cfg)
		if err != nil {
			return nil, err
		}
		if settings.Index != old.Index {
			return nil, fmt.Errorf("owned interface identity changed while reading IPv6 settings")
		}
		ipv6Snapshot = &settings
	}
	var undo undoStack
	ipv4Undo := windowsRestoreBatch{network: n}
	undo.add("IPv4 interface", ipv4Undo.restore)
	apply := func(name, script, restore string, params any) error {
		// Property setters can complete before a timeout is observed. Restore
		// the saved value even if an attempted command reports an error.
		if ipv6Snapshot != nil {
			restore = ownedIPv6Identity + restore
		}
		ipv4Undo.add(name, restore, params)
		if _, err := n.powershell(ctx, script, params); err != nil {
			return err
		}
		return nil
	}
	p := map[string]any{"Index": old.Index, "IP": ip.String(), "Prefix": prefix, "MTU": MTU, "OldMTU": old.MTU, "Metric": old.Metric, "Auto": old.AutomaticMetric, "DNS": old.DNS, "StaticDNS": old.StaticDNS}
	if ipv6Snapshot != nil {
		p["Name"], p["GUID"] = d.Name(), ipv6Snapshot.GUID
	}
	if _, owned := d.(*singDevice); owned {
		// A newly owned L3 adapter needs the same kernel TCP prerequisites as
		// sing-tun's native Windows configurator. Device removal rolls these
		// temporary interface flags back; no pre-existing adapter is changed.
		if _, err := n.powershell(ctx, `Set-NetIPInterface -InterfaceIndex $p.Index -AddressFamily IPv4 -Forwarding Enabled -RouterDiscovery Disabled -DadTransmits 0`, p); err != nil {
			return nil, err
		}
	}
	if err := apply("MTU", `Set-NetIPInterface -InterfaceIndex $p.Index -AddressFamily IPv4 -NlMtuBytes $p.MTU`, `Set-NetIPInterface -InterfaceIndex $p.Index -AddressFamily IPv4 -NlMtuBytes $p.OldMTU`, p); err != nil {
		return undo.restore, err
	}
	if err := apply("metric", `Set-NetIPInterface -InterfaceIndex $p.Index -AddressFamily IPv4 -AutomaticMetric Disabled -InterfaceMetric 1`, `if($p.Auto -eq 'Enabled'){Set-NetIPInterface -InterfaceIndex $p.Index -AddressFamily IPv4 -AutomaticMetric Enabled}else{Set-NetIPInterface -InterfaceIndex $p.Index -AddressFamily IPv4 -AutomaticMetric Disabled -InterfaceMetric $p.Metric}`, p); err != nil {
		return undo.restore, err
	}
	if old.DHCP == "Enabled" {
		if err := apply("DHCP", `Set-NetIPInterface -InterfaceIndex $p.Index -AddressFamily IPv4 -Dhcp Disabled`, `Set-NetIPInterface -InterfaceIndex $p.Index -AddressFamily IPv4 -Dhcp Enabled`, p); err != nil {
			return undo.restore, err
		}
	}
	if err := apply("address", `New-NetIPAddress -InterfaceIndex $p.Index -IPAddress $p.IP -PrefixLength $p.Prefix -PolicyStore ActiveStore | Out-Null`, `Get-NetIPAddress -InterfaceIndex $p.Index -IPAddress $p.IP -PrefixLength $p.Prefix -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false`, p); err != nil {
		return undo.restore, err
	}
	if err := apply("DNS", `Get-DnsClientServerAddress -InterfaceIndex $p.Index -AddressFamily IPv4 | Set-DnsClientServerAddress -ServerAddresses @($p.IP)`, `$dns=Get-DnsClientServerAddress -InterfaceIndex $p.Index -AddressFamily IPv4; if($p.StaticDNS){$dns | Set-DnsClientServerAddress -ServerAddresses @($p.DNS)}else{$dns | Set-DnsClientServerAddress -ResetServerAddresses}`, p); err != nil {
		return undo.restore, err
	}
	if ipv6Snapshot != nil {
		cleanup, err := n.configureIPv6(ctx, d, cfg, *ipv6Snapshot)
		undo.add("IPv6 interface", cleanup)
		if err != nil {
			return undo.restore, err
		}
	}
	return undo.restore, nil
}

func (n systemNetwork) AddRoute(ctx context.Context, d Device, subnet *net.IPNet) (Cleanup, error) {
	if subnet != nil && subnet.IP.To4() == nil {
		return n.addWindowsIPv6Route(ctx, d, subnet)
	}
	p := map[string]any{"Name": d.Name(), "Prefix": subnet.String(), "Gateway": n.gateway}
	data, err := n.powershell(ctx, `$a=Get-NetAdapter -Name ([System.Management.Automation.WildcardPattern]::Escape($p.Name)); @(Get-NetRoute -DestinationPrefix $p.Prefix -InterfaceIndex $a.ifIndex -PolicyStore ActiveStore -AddressFamily IPv4 -NextHop $p.Gateway -ErrorAction SilentlyContinue).Count | ConvertTo-Json`, p)
	if err != nil {
		return nil, err
	}
	var count int
	if err := json.Unmarshal(data, &count); err != nil {
		return nil, err
	}
	if count != 0 {
		return nil, fmt.Errorf("route %s already exists on %s", subnet, d.Name())
	}
	cleanup := func(ctx context.Context) error {
		_, err := n.powershell(ctx, `$a=Get-NetAdapter -Name ([System.Management.Automation.WildcardPattern]::Escape($p.Name)); Get-NetRoute -DestinationPrefix $p.Prefix -InterfaceIndex $a.ifIndex -PolicyStore ActiveStore -AddressFamily IPv4 -NextHop $p.Gateway -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false`, p)
		return err
	}
	_, err = n.powershell(ctx, `$a=Get-NetAdapter -Name ([System.Management.Automation.WildcardPattern]::Escape($p.Name)); New-NetRoute -DestinationPrefix $p.Prefix -InterfaceIndex $a.ifIndex -PolicyStore ActiveStore -AddressFamily IPv4 -NextHop $p.Gateway | Out-Null`, p)
	return cleanup, err
}

func fixTunIP(ip net.IP) net.IP { return ip }

// Establish the required TCP exception explicitly: upstream's COM firewall
// helper discards errors and can leave an otherwise ready tunnel unusable.
// Scope the rule to this program and owned TUN IP, and remove only our rule.
func (n systemNetwork) PrepareStack(ctx context.Context, cfg CoreConfig) (Cleanup, error) {
	path, err := filepath.Abs(os.Args[0])
	if err != nil {
		return nil, err
	}
	// Firewall application filters need the canonical executable path. In
	// particular, go test can run from a DOS 8.3 TEMP path (RUNNER~1).
	program, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, fmt.Errorf("resolve firewall executable: %w", err)
	}
	ip, _, err := net.ParseCIDR(cfg.Network)
	if err != nil {
		return nil, err
	}
	// Keep the upstream display name so its helper recognizes the exception,
	// but use a unique safe ID to clean up exactly the rule we created.
	p := map[string]any{"Name": "Kone-TCP-" + rand.Text(), "Rule": "sing-tun (" + path + ")", "Program": program, "IP": ip.String()}
	if cfg.IPv6Network != "" {
		ipv6, _, err := net.ParseCIDR(cfg.IPv6Network)
		if err != nil {
			return nil, err
		}
		p["IP"] = []string{ip.String(), ipv6.String()}
	}
	data, err := n.powershell(ctx, `@(Get-NetFirewallRule -ErrorAction Stop | Where-Object { $_.DisplayName -eq $p.Rule }).Count | ConvertTo-Json`, p)
	if err != nil {
		return nil, err
	}
	var count int
	if err := json.Unmarshal(data, &count); err != nil {
		return nil, err
	}
	if count > 0 {
		return nil, nil
	}
	cleanup := func(ctx context.Context) error {
		_, err := n.powershell(ctx, `Get-NetFirewallRule -ErrorAction Stop | Where-Object { $_.Name -eq $p.Name } | Remove-NetFirewallRule`, p)
		return err
	}
	_, err = n.powershell(ctx, `New-NetFirewallRule -Name $p.Name -DisplayName $p.Rule -Program $p.Program -LocalAddress $p.IP -Direction Inbound -Action Allow -Protocol TCP -Profile Any | Out-Null`, p)
	if err != nil {
		err = fmt.Errorf("create TCP firewall exception for %q at %s: %w", program, ip, err)
	}
	return cleanup, err
}
