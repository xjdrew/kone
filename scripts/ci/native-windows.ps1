# CI only. Run from the source checkout under test, without changing directory.
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('tun')]
  [string] $Action
)

$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -cne 'true') {
  throw 'Native Windows acceptance is restricted to disposable GitHub Actions runners.'
}
if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)) {
  throw 'Native Windows acceptance requires a Windows runner.'
}
if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP) -or
    -not [IO.Path]::IsPathFullyQualified($env:RUNNER_TEMP) -or
    -not (Test-Path -LiteralPath $env:RUNNER_TEMP -PathType Container)) {
  throw 'Native Windows acceptance requires an existing absolute RUNNER_TEMP.'
}
if ($env:KONE_WINDOWS_SYSTEM_TEST -cne '1' -or $env:KONE_TEST_STACK -cnotin @('system', 'mixed')) {
  throw 'Requires KONE_WINDOWS_SYSTEM_TEST=1 and KONE_TEST_STACK=system or mixed.'
}

$pattern = '^TestSystemWindows(Wintun|IPv6Wintun)$/^' + $env:KONE_TEST_STACK + '$'
go test -tags with_gvisor -race -failfast -count=1 -timeout 12m -run $pattern -json ./test/integration | Tee-Object -FilePath native-windows.jsonl
$result = $LASTEXITCODE
$events = Get-Content native-windows.jsonl | ConvertFrom-Json
$events | Where-Object Output | ForEach-Object { Write-Host -NoNewline $_.Output }
if ($result -ne 0) { exit $result }
$passed = @($events | Where-Object { $_.Action -eq 'pass' } | ForEach-Object Test)
$stack = $env:KONE_TEST_STACK
foreach ($case in @('traffic', 'udp6_rollback', 'tcp6_rollback', 'route_rollback')) {
  if ($passed -notcontains "TestSystemWindowsIPv6Wintun/$stack/$case") {
    throw "Missing actual IPv6 pass: $stack/$case"
  }
}
foreach ($occupied in @('true', 'false')) {
  if ($passed -notcontains "TestSystemWindowsWintun/$stack/occupied=$occupied") {
    throw "Missing actual IPv4 pass: $stack/occupied=$occupied"
  }
}
$other = if ($stack -eq 'system') { 'mixed' } else { 'system' }
if (@($events | Where-Object { $_.Test -match "^TestSystemWindows(Wintun|IPv6Wintun)/$other/" }).Count -ne 0) {
  throw 'Unexpected stack executed on this runner'
}
