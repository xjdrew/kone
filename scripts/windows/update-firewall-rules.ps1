#Requires -Version 3
#Requires -RunAsAdministrator
#Requires -Modules NetSecurity
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $Program,
    [ValidateSet('Any', 'Domain', 'Private', 'Public')]
    [string[]] $Profiles = @('Domain', 'Private')
)

$Program = (Resolve-Path -LiteralPath $Program).Path
foreach ($Protocol in @('TCP', 'UDP')) {
    $RuleName = "Kone-$Protocol"
    Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -Name $RuleName -DisplayName 'Kone' `
        -Profile $Profiles -Description 'Work with Kone.' -Direction Inbound `
        -Protocol $Protocol -Action Allow -Program $Program | Out-Null
}
