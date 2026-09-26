param([switch]$IncludeTor)
$state = Join-Path $env:LOCALAPPDATA 'umbra'
foreach ($name in @('worker', 'serve')) {
    $identityFile = Join-Path $state "$name.process.json"
    $records = @(Get-Content -LiteralPath $identityFile -ErrorAction SilentlyContinue | ConvertFrom-Json)
    if (-not $records) { Write-Host "$name has no saved identity; refusing to guess from an old PID."; continue }
    foreach ($record in $records) {
        if (-not $record) { continue }
        $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$($record.id)" -ErrorAction SilentlyContinue
        if ($proc -and $proc.ExecutablePath -eq $record.exe -and $proc.CreationDate.ToUniversalTime() -eq ([datetime]$record.created).ToUniversalTime()) {
            Stop-Process -Id $record.id
            Write-Host "Stopped verified $name process $($record.id)"
        }
    }
}
if ($IncludeTor) {
    Write-Host 'Tor is shared and remains running. Stop its verified process separately if no other tools use it.'
}
