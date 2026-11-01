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
if ($env:KONE_WINDOWS_SYSTEM_TEST -cne '1') {
  throw 'Requires KONE_WINDOWS_SYSTEM_TEST=1.'
}
$stacks = @('system', 'mixed')
# Source-relative capability marker: older release SHAs support two stacks.
if (Test-Path -LiteralPath 'pkg/kone/stack_modes.go') { $stacks = @('system', 'gvisor', 'mixed') }
if ($env:KONE_TEST_STACK -ceq 'gvisor' -and $stacks -cnotcontains 'gvisor') {
  Write-Host 'Historical source has no gvisor runtime mode; this matrix entry is not applicable.'
  exit 0
}
if (-not [string]::IsNullOrEmpty($env:KONE_TEST_STACK)) {
  if ($env:KONE_TEST_STACK -cnotin $stacks) { throw 'Unsupported KONE_TEST_STACK for this source.' }
  $stacks = @($env:KONE_TEST_STACK)
}
$binary = Join-Path $env:RUNNER_TEMP 'kone-windows-system.test.exe'
. (Join-Path $PSScriptRoot 'windows-test-arguments.ps1')
$buildArguments = @('test', '-tags', 'with_gvisor', '-race', '-c', '-o', $binary, './test/integration')
& go @buildArguments
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
# Separate test processes, one at a time, so Wintun/routes never overlap stacks.
foreach ($stack in $stacks) {
  $env:KONE_TEST_STACK = $stack
  $output = "native-windows-$stack.jsonl"
  $testArguments = Get-KoneWindowsTestArguments -Binary $binary -Stack $stack
  & go @testArguments | Tee-Object -FilePath $output
  $result = $LASTEXITCODE
  $events = Get-Content -LiteralPath $output | ConvertFrom-Json
  $events | Where-Object Output | ForEach-Object { Write-Host -NoNewline $_.Output }
  if ($result -ne 0) { exit $result }
  $passed = @($events | Where-Object { $_.Action -eq 'pass' } | ForEach-Object Test)
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
  $unexpected = @($events | Where-Object {
    $_.Test -match '^TestSystemWindows(Wintun|IPv6Wintun)/([^/]+)/' -and $Matches[2] -cne $stack
  })
  if ($unexpected.Count -ne 0) {
    throw 'Unexpected stack executed in this test process'
  }
}
