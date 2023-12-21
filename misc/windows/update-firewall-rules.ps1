# $Program should direct to execute file
Remove-NetFirewallRule -Description "Work with Kone." -ErrorAction SilentlyContinue
'TCP', 'UDP' | ForEach-Object {
    New-NetFirewallRule `
        -DisplayName "Kone" `
        -Profile "Any" `
        -Description "Work with Kone." `
        -Direction Inbound `
        -Protocol $_ `
        -Action Allow `
        -Program "E:\go\github\kone\kone.exe" `
    | Out-Null
}