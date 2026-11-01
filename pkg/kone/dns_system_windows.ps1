# Embedded in the Windows resolver controller. No parameter becomes source code.
# This process owns the machine-wide mutex for the complete NRPT lease lifetime.
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$ledgerPath = 'SOFTWARE\Kone\DNSLeases'
$mutexName = 'Global\Kone.SystemDNS.v1'
$script:reason = 'unavailable'

function Fail([string]$reason) { $script:reason=$reason; throw 'Windows DNS lease refused.' }

function Emit($value) {
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject $value -Depth 12 -Compress))
    [Console]::Out.Flush()
}
function LocalRules { @(Get-DnsClientNrptRule -ErrorAction Stop) }
function RootRules($rules) { @($rules | Where-Object { @($_.Namespace) -contains '.' }) }
function Tag($record) { 'KONE DNS lease ' + $record.ID }
function Note($record) { 'KONE/v1;' + $record.ID + ';' + $record.GUID + ';' + $record.Address + ';' + $record.LUID }
function ExactRule($rule, $record) {
    # All configurable rule fields are checked, including disabled security
    # features: recovery must not erase a policy changed by another owner.
    if ($rule.Version -ne 2 -or @($rule.Namespace).Count -ne 1 -or $rule.Namespace[0] -cne '.' -or
        [string]$rule.NameServers -cne $record.Address -or
        [string]$rule.DisplayName -cne (Tag $record) -or
        [string]$rule.Comment -cne (Note $record) -or
        [string]$rule.NameEncoding -cne 'Disable' -or
        $rule.DirectAccessEnabled -or $rule.DnsSecEnabled -or
        $rule.DnsSecValidationRequired -or $rule.DirectAccessQueryIPsecRequired -or
        $rule.DnsSecQueryIPsecRequired) { return $false }
    foreach ($property in @('IPsecCARestriction','DirectAccessDnsServers','DirectAccessProxyName',
        'DirectAccessQueryIPsecEncryption','DnsSecQueryIPsecEncryption')) {
        if (-not [string]::IsNullOrEmpty([string]$rule.$property) -and [string]$rule.$property -cne 'None') { return $false }
    }
    if (-not [string]::IsNullOrEmpty([string]$rule.DirectAccessProxyType) -and
        [string]$rule.DirectAccessProxyType -cne 'NoProxy') { return $false }
    if ($record.RuleName -and [string]$rule.Name -cne $record.RuleName) { return $false }
    return $true
}
function CandidateRules($rules, $record) {
    # RuleName is absent in a pending journal. Either token-bearing field then
    # finds Add's auto-generated name even if the parent died before its ACK.
    @($rules | Where-Object {
        ($record.RuleName -and [string]$_.Name -ceq $record.RuleName) -or
        [string]$_.DisplayName -ceq (Tag $record) -or [string]$_.Comment -ceq (Note $record)
    })
}
function VerifyLedgerACL($key) {
    $acl = $key.GetAccessControl()
    if (-not $acl.AreAccessRulesProtected -or
        $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cnotin @('S-1-5-18','S-1-5-32-544')) {
        Fail 'changed'
    }
    $writes = [Security.AccessControl.RegistryRights]::SetValue -bor
        [Security.AccessControl.RegistryRights]::CreateSubKey -bor
        [Security.AccessControl.RegistryRights]::Delete -bor
        [Security.AccessControl.RegistryRights]::ChangePermissions -bor
        [Security.AccessControl.RegistryRights]::TakeOwnership
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            ($rule.RegistryRights -band $writes) -ne 0 -and
            $rule.IdentityReference.Value -cnotin @('S-1-5-18','S-1-5-32-544')) {
            Fail 'changed'
        }
    }
}
function ReadLedger {
    $root = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($ledgerPath)
    if ($null -eq $root) { return @() }
    try {
        VerifyLedgerACL $root
        $names = @($root.GetSubKeyNames())
        if ($names.Count -gt 16) { throw 'Too many resolver lease records; inspect local policy.' }
        $records = @()
        foreach ($name in $names) {
            if ($name -cnotmatch '^[a-f0-9]{32}$') { throw 'Invalid resolver lease identity.' }
            $key = $root.OpenSubKey($name)
            try {
                VerifyLedgerACL $key
                $json = [string]$key.GetValue('Record', $null)
                if ($json.Length -gt 8192 -or [string]::IsNullOrEmpty($json)) { throw 'Invalid resolver lease record.' }
                $record = $json | ConvertFrom-Json
                if ($record.Version -ne 1 -or $record.ID -cne $name -or
                    $record.GUID -cnotmatch '^[a-f0-9-]{36}$' -or $record.DeviceIndex -le 0 -or
                    $record.LUID -cnotmatch '^[0-9]{1,20}$' -or [uint64]$record.LUID -eq 0 -or
                    $record.WorkerPID -le 0 -or $record.WorkerStart -le 0 -or
                    $record.DeviceName.Length -gt 256 -or $record.DeviceName.Length -eq 0 -or
                    $record.Address -cnotmatch '^([0-9]{1,3}\.){3}[0-9]{1,3}$' -or
                    $record.RuleName.Length -gt 64) { throw 'Invalid resolver lease metadata.' }
                $records += $record
            } finally { if ($key) { $key.Dispose() } }
        }
        return $records
    } finally { $root.Dispose() }
}
function SaveLedger($record) {
    $acl = [Security.AccessControl.RegistrySecurity]::new()
    # The manager may inspect public ownership metadata without elevation.
    # Only SYSTEM and administrators can replace/delete records, across UAC users.
    $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)')
    $root = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($ledgerPath,
        [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, $acl)
    try {
        $key = $root.CreateSubKey($record.ID,
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, $acl)
        try {
            $key.SetValue('Record', (ConvertTo-Json -InputObject $record -Depth 5 -Compress),
                [Microsoft.Win32.RegistryValueKind]::String)
            $key.Flush() # Intent is durable before Add-DnsClientNrptRule.
        } finally { $key.Dispose() }
        $root.Flush()
    } finally { $root.Dispose() }
}
function DeleteLedger($record) {
    $current = @(ReadLedger | Where-Object { $_.ID -ceq $record.ID })
    if ($current.Count -ne 1 -or
        (ConvertTo-Json -InputObject $current[0] -Compress) -cne (ConvertTo-Json -InputObject $record -Compress)) {
        throw 'Resolver lease record changed; it was preserved.'
    }
    $root = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($ledgerPath, $true)
    try { $root.DeleteSubKey($record.ID, $true); $root.Flush() } finally { $root.Dispose() }
}
function OwnerAlive($record) {
    try {
        $process = Get-Process -Id $record.WorkerPID -ErrorAction Stop
        return $process.StartTime.ToUniversalTime().Ticks -eq $record.WorkerStart
    } catch {
        # An inaccessible live process is not proof that its lease is orphaned.
        if ($_.FullyQualifiedErrorId -like 'NoProcessFoundForGivenId*') { return $false }
        return $true
    }
}
function TakeMutex {
    $acl = [Security.AccessControl.MutexSecurity]::new()
    $acl.SetSecurityDescriptorSddlForm('D:P(A;;GA;;;SY)(A;;GA;;;BA)')
    $created = $false
    $script:mutex = [Threading.Mutex]::new($false, $mutexName, [ref]$created, $acl)
    try { $script:locked = $script:mutex.WaitOne(0) }
    catch [Threading.AbandonedMutexException] { $script:locked = $true }
    if (-not $script:locked) { Fail 'lease_busy' }
}
function Restore($record) {
    $rules = @(LocalRules)
    $matches = @(CandidateRules $rules $record)
    if ($matches.Count -eq 0) {
        if (-not $record.RuleName -and @(RootRules $rules).Count -ne 0) {
            Fail 'changed'
        }
        DeleteLedger $record
        return
    }
    if ($matches.Count -ne 1 -or -not (ExactRule $matches[0] $record)) {
        Fail 'changed'
    }
    Remove-DnsClientNrptRule -Name ([string]$matches[0].Name) -Force -ErrorAction Stop
    if (@(CandidateRules @(LocalRules) $record).Count -ne 0) { throw 'Resolver rule removal was not confirmed.' }
    DeleteLedger $record
}
function PolicyAvailable {
    foreach ($command in @('Get-DnsClientNrptRule','Get-DnsClientNrptPolicy','Get-DnsClientNrptGlobal','Add-DnsClientNrptRule','Remove-DnsClientNrptRule')) {
        $null = Get-Command $command -ErrorAction Stop
    }
    $global = Get-DnsClientNrptGlobal -ErrorAction Stop
    foreach ($setting in @('EnableDAForAllNetworks','QueryPolicy','SecureNameQueryFallback')) {
        if (-not [string]::IsNullOrEmpty([string]$global.$setting) -and [string]$global.$setting -cne 'Disable') {
            Fail 'domain_policy'
        }
    }
    if (@(RootRules @(LocalRules)).Count -ne 0 -or
        @(RootRules @(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop)).Count -ne 0) {
        Fail 'root_policy_conflict'
    }
    # Domain policy can make every local NRPT rule ineffective, even when the
    # domain's own namespaces are more specific. Never bypass that policy.
    $policy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    if (Test-Path -LiteralPath ($policy + '\DnsPolicyConfig')) {
        if (@(Get-ChildItem -LiteralPath ($policy + '\DnsPolicyConfig')).Count -ne 0) {
            Fail 'domain_policy'
        }
    }
    if (Test-Path -LiteralPath $policy) {
        $doh = (Get-ItemProperty -LiteralPath $policy).PSObject.Properties['DoHPolicy']
        if ($doh -and [int]$doh.Value -eq 3) { Fail 'encrypted_policy' }
    }
    if (Get-Command Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue) {
        $configured = @(Get-DnsClientServerAddress -ErrorAction Stop | ForEach-Object { $_.ServerAddresses })
        $strict = @(Get-DnsClientDohServerAddress -ErrorAction Stop | Where-Object {
            $_.AutoUpgrade -and -not $_.AllowFallbackToUdp -and $_.ServerAddress -in $configured
        })
        if ($strict.Count -ne 0) { Fail 'encrypted_policy' }
    }
    if (@(ReadLedger).Count -ne 0) { Fail 'lease_busy' }
}
function Verify($record) {
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { $_.ifIndex -eq $record.DeviceIndex })
    if ($adapters.Count -ne 1) { Fail 'changed' }
    $adapter = $adapters[0]
    if ([string]$adapter.Name -cne $record.DeviceName -or
        [string]$adapter.NetLuid -cne $record.LUID -or
        ([guid]$adapter.InterfaceGuid).ToString('D') -cne $record.GUID) { Fail 'changed' }
    $matches = @(CandidateRules @(LocalRules) $record)
    if ($matches.Count -ne 1 -or -not (ExactRule $matches[0] $record)) { Fail 'changed' }
    $roots = @(RootRules @(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop))
    if ($roots.Count -ne 1 -or [string]$roots[0].NameServers -cne $record.Address) {
        Fail 'changed'
    }
}

$script:mutex = $null
$script:locked = $false
$record = $null
try {
    if ($p.Action -ceq 'context') {
        $snapshot = KoneReadContext | ConvertFrom-Json
        $rules = @(LocalRules)
        $excluded = @()
        foreach ($item in @(ReadLedger)) {
            $matches = @(CandidateRules $rules $item)
            if ($matches.Count -ne 1 -or -not (ExactRule $matches[0] $item)) {
                Fail 'changed'
            }
            $excluded += $item.Address
            $snapshot.nrpt = @($snapshot.nrpt | Where-Object {
                -not (@($_.namespaces).Count -eq 1 -and $_.namespaces[0] -ceq '.' -and
                    @($_.servers).Count -eq 1 -and $_.servers[0] -ceq $item.Address)
            })
            $snapshot.links = @($snapshot.links | Where-Object {
                -not ($_.index -eq $item.DeviceIndex -and $_.name -ceq $item.DeviceName)
            })
        }
        if ($excluded.Count -gt 0) {
            $defaults = @($p.Servers | Where-Object { ($_ -replace ':53$','') -cnotin $excluded })
            if ($defaults.Count -eq 0) {
                $routes = @($snapshot.routes | Where-Object { $_.prefix -ceq '0.0.0.0/0' } | Sort-Object metric)
                if ($routes.Count -gt 0) {
                    $preferred = @($routes | Where-Object { $_.metric -eq $routes[0].metric } | Select-Object -ExpandProperty interface -Unique)
                    if ($preferred.Count -eq 1) {
                        $defaults = @($snapshot.links | Where-Object { $_.name -ceq $preferred[0] } |
                            ForEach-Object { $_.servers } | Where-Object { $_ -cnotin $excluded })
                    }
                }
            }
            $snapshot | Add-Member -NotePropertyName owned_excluded -NotePropertyValue $true
            $snapshot | Add-Member -NotePropertyName default_servers -NotePropertyValue @($defaults)
        }
        Emit @{context=$snapshot}; return
    }
    if ($p.Action -ceq 'check') { PolicyAvailable; Emit @{ok=$true}; return }
    if ($p.Action -ceq 'inspect') {
        $rules = @(LocalRules)
        $entries = @()
        foreach ($item in @(ReadLedger)) {
            $matches = @(CandidateRules $rules $item)
            $safe = $matches.Count -eq 1 -and (ExactRule $matches[0] $item)
            if ($matches.Count -eq 0 -and ($item.RuleName -or @(RootRules $rules).Count -eq 0)) { $safe = $true }
            $alive = OwnerAlive $item
            $status = 'orphaned'
            $message = 'An interrupted KONE resolver lease requires elevated recovery.'
            if ($alive) { $status='active'; $message='Another KONE process still owns this resolver lease.' }
            elseif (-not $safe) { $status='changed'; $message='Resolver ownership or policy changed; automatic removal is blocked.' }
            $entries += @{id=$item.ID;device_name=$item.DeviceName;device_index=$item.DeviceIndex;
                rule_name=$item.RuleName;status=$status;can_recover=($safe -and -not $alive);message=$message}
        }
        Emit @{entries=$entries}; return
    }
    TakeMutex
    if ($p.Action -ceq 'recover') {
        $records = @(ReadLedger | Where-Object { $_.ID -ceq $p.ID })
        if ($records.Count -ne 1) { throw 'Resolver lease is absent or replaced; refresh recovery information.' }
        if (OwnerAlive $records[0]) { Fail 'lease_busy' }
        Restore $records[0]
        Emit @{ok=$true}; return
    }
    if ($p.Action -cne 'lease') { throw 'Unsupported resolver action.' }
    PolicyAvailable
    $adapter = Get-NetAdapter -Name ([Management.Automation.WildcardPattern]::Escape($p.DeviceName)) -ErrorAction Stop
    if ([int]$adapter.ifIndex -ne $p.DeviceIndex -or [string]$adapter.NetLuid -cne $p.LUID) { Fail 'changed' }
    $addresses = @(Get-NetIPAddress -InterfaceIndex $p.DeviceIndex -AddressFamily IPv4 -ErrorAction Stop)
    if (@($addresses | Where-Object { $_.IPAddress -ceq $p.Address }).Count -ne 1) { throw 'Owned DNS address is not configured.' }
    $record = [pscustomobject][ordered]@{Version=1;ID=$p.ID;DeviceName=$p.DeviceName;DeviceIndex=$p.DeviceIndex;
        GUID=([guid]$adapter.InterfaceGuid).ToString('D');LUID=$p.LUID;Address=$p.Address;RuleName='';
        WorkerPID=$PID;WorkerStart=(Get-Process -Id $PID).StartTime.ToUniversalTime().Ticks}
    SaveLedger $record
    $added = Add-DnsClientNrptRule -Namespace @('.') -NameServers @($record.Address) -NameEncoding Disable `
        -DisplayName (Tag $record) -Comment (Note $record) -PassThru -ErrorAction Stop
    if (-not (ExactRule $added $record)) { throw 'Created resolver rule could not be verified.' }
    $record.RuleName = [string]$added.Name
    SaveLedger $record
    Verify $record
    Emit @{ok=$true;id=$record.ID}
    while ($true) {
        $line = [Console]::In.ReadLine()
        if ($null -eq $line -or $line -ceq 'stop') { break }
        if ($line -cne 'verify') { throw 'Unexpected resolver lease command.' }
        Verify $record
        Emit @{ok=$true}
    }
    Restore $record
    $record = $null
    Emit @{ok=$true;stopped=$true}
} catch {
    # Fixed errors originate in this controller; OS errors may contain private
    # resolver metadata. Do not forward cmdlet diagnostics to GUI logs.
    Emit @{ok=$false;code=$script:reason;error='Windows system DNS lease could not be verified or restored; inspect local recovery status.'}
    exit 1
} finally {
    if ($record) {
        try { Restore $record } catch { } # Changed policy intentionally survives.
    }
    if ($script:locked) { $script:mutex.ReleaseMutex() }
    if ($script:mutex) { $script:mutex.Dispose() }
}
