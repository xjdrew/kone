# Pure argument construction only. Native-runner checks remain in the caller.
function Get-KoneWindowsTestArguments {
  param(
    [Parameter(Mandatory = $true)] [string] $Binary,
    [Parameter(Mandatory = $true)] [ValidateSet('system', 'gvisor', 'mixed')] [string] $Stack
  )
  $pattern = '^TestSystemWindows(Wintun|IPv6Wintun|DNS)$/^' + $Stack + '$'
  return @(
    'tool', 'test2json', '-t', '-p', 'github.com/xjdrew/kone/test/integration',
    $Binary, '-test.run', $pattern, '-test.v=test2json', '-test.failfast',
    '-test.count=1', '-test.timeout', '12m'
  )
}
