Remove-NetFirewallRule -Description "Work with Kone." -ErrorAction SilentlyContinue
'TCP', 'UDP' | ForEach-Object {
    New-NetFirewallRule `
        -DisplayName "Kone" `
        -Profile "Private, Public" `
        -Description "Work with Kone." `
        -Direction Inbound `
        -Protocol $_ `
        -Action Allow `
        -Program "E:\go\github\kone\kone.exe" `
        -EdgeTraversalPolicy DeferToUser `
    | Out-Null
}