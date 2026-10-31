package kone

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/windows"
)

type windowsIPv6Settings struct {
	Index, MTU, Metric, DadTransmits                                int
	GUID, AutomaticMetric, DHCP, RouterDiscovery, Managed, Stateful string
	Addresses                                                       []struct {
		IPAddress    string
		PrefixLength int
	}
}

const readWindowsIPv6Settings = `
$a=Get-NetAdapter -Name ([System.Management.Automation.WildcardPattern]::Escape($p.Name));
$i=Get-NetIPInterface -InterfaceIndex $a.ifIndex -AddressFamily IPv6 -PolicyStore ActiveStore;
try { $addresses=@(Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv6 -ErrorAction Stop) } catch { if($_.FullyQualifiedErrorId -notlike 'CmdletizationQuery_NotFound*'){throw}; $addresses=@() };
[pscustomobject]@{Index=[int]$a.ifIndex;GUID=([guid]$a.InterfaceGuid).ToString('B');MTU=[int]$i.NlMtu;Metric=[int]$i.InterfaceMetric;AutomaticMetric=$i.AutomaticMetric.ToString();DHCP=$i.Dhcp.ToString();RouterDiscovery=$i.RouterDiscovery.ToString();DadTransmits=[int]$i.DadTransmits;Managed=$i.ManagedAddressConfiguration.ToString();Stateful=$i.OtherStatefulConfiguration.ToString();Addresses=@($addresses | Select-Object IPAddress,PrefixLength)} | ConvertTo-Json -Depth 5 -Compress`

const ownedIPv6Identity = `$a=Get-NetAdapter -Name ([System.Management.Automation.WildcardPattern]::Escape($p.Name)); if([int]$a.ifIndex -ne $p.Index -or [guid]$a.InterfaceGuid -ne [guid]$p.GUID){throw 'owned IPv6 interface identity changed'}; `

func (n systemNetwork) readIPv6Settings(ctx context.Context, d Device, cfg CoreConfig) (windowsIPv6Settings, error) {
	var settings windowsIPv6Settings
	data, err := n.powershell(ctx, readWindowsIPv6Settings, map[string]any{"Name": d.Name()})
	if err != nil {
		return settings, err
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		return settings, fmt.Errorf("read IPv6 interface snapshot: %w", err)
	}
	_, guidErr := windows.GUIDFromString(settings.GUID)
	enabled := func(value string) bool { return value == "Enabled" || value == "Disabled" }
	if settings.Index <= 0 || guidErr != nil || settings.MTU < 1280 || settings.Metric < 0 || settings.DadTransmits < 0 || settings.DadTransmits > 32 || !enabled(settings.AutomaticMetric) || !enabled(settings.DHCP) || !enabled(settings.Managed) || !enabled(settings.Stateful) || settings.RouterDiscovery != "Enabled" && settings.RouterDiscovery != "Disabled" && settings.RouterDiscovery != "ControlledByDHCP" {
		return settings, errors.New("invalid IPv6 interface snapshot")
	}
	ip, _, err := net.ParseCIDR(cfg.IPv6Network)
	if err != nil || ip.To4() != nil {
		return settings, errors.New("invalid owned IPv6 address")
	}
	for _, address := range settings.Addresses {
		if parsed := net.ParseIP(address.IPAddress); parsed != nil && parsed.Equal(ip) {
			return settings, fmt.Errorf("virtual IPv6 address %s already exists on %s", ip, d.Name())
		}
	}
	return settings, nil
}

func (n systemNetwork) configureIPv6(ctx context.Context, d Device, cfg CoreConfig, old windowsIPv6Settings) (Cleanup, error) {
	ip, subnet, _ := net.ParseCIDR(cfg.IPv6Network)
	prefix, _ := subnet.Mask.Size()
	p := map[string]any{"Name": d.Name(), "Index": old.Index, "GUID": old.GUID, "IP": ip.String(), "Prefix": prefix, "MTU": MTU, "OldMTU": old.MTU, "Metric": old.Metric, "Auto": old.AutomaticMetric, "DHCP": old.DHCP, "Router": old.RouterDiscovery, "Dad": old.DadTransmits, "Managed": old.Managed, "Stateful": old.Stateful}
	undo := windowsRestoreBatch{network: n}
	apply := func(name, script, restore string) error {
		undo.add(name, ownedIPv6Identity+restore, p)
		_, err := n.powershell(ctx, ownedIPv6Identity+script, p)
		return err
	}
	// These are the same IPv6 kernel-TCP prerequisites as sing-tun's Windows
	// configurator. Record attempted writes so a reported partial failure rolls back.
	flags := `Set-NetIPInterface -InterfaceIndex $p.Index -AddressFamily IPv6 -PolicyStore ActiveStore -RouterDiscovery Disabled -DadTransmits 0 -ManagedAddressConfiguration Disabled -OtherStatefulConfiguration Disabled -Dhcp Disabled`
	restoreFlags := `$i=Get-NetIPInterface -InterfaceIndex $p.Index -AddressFamily IPv6 -PolicyStore ActiveStore; if($i.RouterDiscovery.ToString() -notin @('Disabled',$p.Router) -or [int]$i.DadTransmits -notin @(0,$p.Dad) -or $i.ManagedAddressConfiguration.ToString() -notin @('Disabled',$p.Managed) -or $i.OtherStatefulConfiguration.ToString() -notin @('Disabled',$p.Stateful) -or $i.Dhcp.ToString() -notin @('Disabled',$p.DHCP)){throw 'external IPv6 interface flag change; preserving it'}; Set-NetIPInterface -InterfaceIndex $p.Index -AddressFamily IPv6 -PolicyStore ActiveStore -RouterDiscovery $p.Router -DadTransmits $p.Dad -ManagedAddressConfiguration $p.Managed -OtherStatefulConfiguration $p.Stateful -Dhcp $p.DHCP`
	if err := apply("IPv6 kernel flags", flags, restoreFlags); err != nil {
		return undo.restore, err
	}
	if err := apply("IPv6 MTU", `Set-NetIPInterface -InterfaceIndex $p.Index -AddressFamily IPv6 -PolicyStore ActiveStore -NlMtuBytes $p.MTU`, `$i=Get-NetIPInterface -InterfaceIndex $p.Index -AddressFamily IPv6 -PolicyStore ActiveStore; if([int]$i.NlMtu -notin @($p.MTU,$p.OldMTU)){throw 'external IPv6 MTU change; preserving it'}; Set-NetIPInterface -InterfaceIndex $p.Index -AddressFamily IPv6 -PolicyStore ActiveStore -NlMtuBytes $p.OldMTU`); err != nil {
		return undo.restore, err
	}
	if err := apply("IPv6 metric", `Set-NetIPInterface -InterfaceIndex $p.Index -AddressFamily IPv6 -PolicyStore ActiveStore -AutomaticMetric Disabled -InterfaceMetric 1`, `$i=Get-NetIPInterface -InterfaceIndex $p.Index -AddressFamily IPv6 -PolicyStore ActiveStore; if($i.AutomaticMetric.ToString() -notin @('Disabled',$p.Auto) -or [int]$i.InterfaceMetric -notin @(1,$p.Metric)){throw 'external IPv6 metric change; preserving it'}; if($p.Auto -eq 'Enabled'){Set-NetIPInterface -InterfaceIndex $p.Index -AddressFamily IPv6 -PolicyStore ActiveStore -AutomaticMetric Enabled}else{Set-NetIPInterface -InterfaceIndex $p.Index -AddressFamily IPv6 -PolicyStore ActiveStore -AutomaticMetric Disabled -InterfaceMetric $p.Metric}`); err != nil {
		return undo.restore, err
	}
	if err := apply("IPv6 address", `New-NetIPAddress -InterfaceIndex $p.Index -AddressFamily IPv6 -IPAddress $p.IP -PrefixLength $p.Prefix -PolicyStore ActiveStore -SkipAsSource $false | Out-Null`, `$addresses=@(Get-NetIPAddress -InterfaceIndex $p.Index -AddressFamily IPv6 -IPAddress $p.IP -PolicyStore ActiveStore -ErrorAction SilentlyContinue); foreach($address in $addresses){if([int]$address.PrefixLength -ne $p.Prefix -or $address.SkipAsSource -or $address.PrefixOrigin.ToString() -ne 'Manual'){throw 'external IPv6 address change; preserving it'}; $address | Remove-NetIPAddress -Confirm:$false}`); err != nil {
		return undo.restore, err
	}
	return undo.restore, nil
}

func (n systemNetwork) addWindowsIPv6Route(ctx context.Context, d Device, subnet *net.IPNet) (Cleanup, error) {
	p := map[string]any{"Name": d.Name(), "Prefix": subnet.String(), "Gateway": "::"}
	data, err := n.powershell(ctx, `$a=Get-NetAdapter -Name ([System.Management.Automation.WildcardPattern]::Escape($p.Name)); [pscustomobject]@{Index=[int]$a.ifIndex;GUID=([guid]$a.InterfaceGuid).ToString('B');Count=@(Get-NetRoute -DestinationPrefix $p.Prefix -InterfaceIndex $a.ifIndex -PolicyStore ActiveStore -AddressFamily IPv6 -ErrorAction SilentlyContinue).Count} | ConvertTo-Json -Compress`, p)
	if err != nil {
		return nil, err
	}
	var state struct {
		Index, Count int
		GUID         string
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("read IPv6 route ownership: %w", err)
	}
	if _, err := windows.GUIDFromString(state.GUID); err != nil || state.Index <= 0 || state.Count < 0 {
		return nil, errors.New("invalid IPv6 route ownership snapshot")
	}
	if state.Count > 0 {
		return nil, fmt.Errorf("IPv6 route %s already exists on %s", subnet, d.Name())
	}
	p["Index"], p["GUID"] = state.Index, state.GUID
	cleanup := func(ctx context.Context) error {
		_, err := n.powershell(ctx, ownedIPv6Identity+`Get-NetRoute -DestinationPrefix $p.Prefix -InterfaceIndex $p.Index -PolicyStore ActiveStore -AddressFamily IPv6 -NextHop $p.Gateway -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false`, p)
		return err
	}
	_, err = n.powershell(ctx, ownedIPv6Identity+`New-NetRoute -DestinationPrefix $p.Prefix -InterfaceIndex $p.Index -PolicyStore ActiveStore -AddressFamily IPv6 -NextHop $p.Gateway -RouteMetric 1 | Out-Null`, p)
	return cleanup, err
}
