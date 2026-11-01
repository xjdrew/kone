param([string]$Prefix = (Join-Path $env:LOCALAPPDATA 'Programs\Kone'))
$ErrorActionPreference = 'Stop'
# A per-user installation; no elevation, services, trust, firewall or network changes.
$KoneInstall = [System.IO.Path]::GetFullPath($Prefix)
New-Item -ItemType Directory -Path $KoneInstall -Force | Out-Null
foreach ($KoneFile in @('kone.exe', 'LICENSE', 'LICENSE-MIT', 'build-info.json', 'README.txt')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $KoneFile) -Destination $KoneInstall -Force
}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'licenses') -Destination $KoneInstall -Recurse -Force
Write-Output "Installed KONE in $KoneInstall. Run kone.exe to open management; capture stays paused."
Write-Output 'The user profile is separate and is preserved during upgrade or manual uninstall.'
