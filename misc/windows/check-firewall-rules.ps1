#Requires -Version 3
#Requires -Modules NetSecurity

$List = Get-NetFirewallRule -Enabled True -Action Allow -Description 'Work with Kone.' | Where-Object { 'Kone' -eq $_.DisplayName }
$Report = foreach ($Rule in $List)
{
    $Program = (Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $Rule).Program

    @{
        Profile     = $Rule.Profile
        Enabled     = $Rule.Enabled
        Action      = $Rule.Action
        Protocol    = (Get-NetFirewallPortFilter -AssociatedNetFirewallRule $Rule).Protocol
        Program     = $Program
        IsPathValid = Test-Path -PathType Leaf -LiteralPath $Program
    }
}
$Report
Pause