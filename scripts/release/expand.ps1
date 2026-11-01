param([Parameter(Mandatory)][string]$Source, [Parameter(Mandatory)][string]$Destination)
$ErrorActionPreference = 'Stop'
Expand-Archive -LiteralPath $Source -DestinationPath $Destination
