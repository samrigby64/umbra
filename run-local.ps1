<#
.SYNOPSIS
  Start Umbra on this machine: the Tor daemon, the API + web GUI, and the crawl worker.

.DESCRIPTION
  Everything lives under %LOCALAPPDATA%\umbra (database, logs, PID files) and
  %LOCALAPPDATA%\umbra-tor (the Tor Expert Bundle). Run this again at any time -
  anything already running is left alone. Stop with .\stop-local.ps1.

  The worker keeps crawling hidden services until stopped. Start with -NoWorker
  if you only want to browse what has already been collected.

.EXAMPLE
  .\run-local.ps1                      # start everything, open http://localhost:8000/
  .\run-local.ps1 -NoWorker            # API + GUI only
  .\run-local.ps1 -IntervalSeconds 180 # crawl pass every 3 minutes instead of 10
#>
param(
    [int]$Port = 8000,
    [int]$IntervalSeconds = 600,
    [switch]$NoWorker
)
$ErrorActionPreference = "Stop"
$root  = Split-Path -Parent $MyInvocation.MyCommand.Path
$py    = Join-Path $root ".venv\Scripts\python.exe"
$state = Join-Path $env:LOCALAPPDATA "umbra"
$tor   = Join-Path $env:LOCALAPPDATA "umbra-tor"
New-Item -ItemType Directory -Force $state | Out-Null

if (-not (Test-Path $py)) {
    throw "No virtualenv at $py - create it first: python -m venv .venv; .\.venv\Scripts\pip install -e `".[api,embeddings]`""
}

function Start-Detached([string]$Name, [string]$File, [string[]]$Arguments, [string]$Cwd) {
    $identityFile = Join-Path $state "$Name.process.json"
    $records = @(Get-Content -LiteralPath $identityFile -ErrorAction SilentlyContinue | ConvertFrom-Json)
    foreach ($record in $records) {
        if (-not $record) { continue }
        $existing = Get-CimInstance Win32_Process -Filter "ProcessId=$($record.id)" -ErrorAction SilentlyContinue
        if ($existing -and $existing.ExecutablePath -eq $record.exe -and $existing.CreationDate.ToUniversalTime() -eq ([datetime]$record.created).ToUniversalTime()) {
            Write-Host "$Name already running (verified process $($record.id))"
            return
        }
    }
    $p = Start-Process -FilePath $File -ArgumentList $Arguments -WorkingDirectory $Cwd -PassThru -WindowStyle Hidden `
        -RedirectStandardError (Join-Path $state "$Name.log") `
        -RedirectStandardOutput (Join-Path $state "$Name.out.log")
    Start-Sleep -Seconds 1
    $processes = @(Get-CimInstance Win32_Process -Filter "ProcessId=$($p.Id) OR ParentProcessId=$($p.Id)")
    $identities = @($processes | ForEach-Object { @{id=$_.ProcessId; exe=$_.ExecutablePath; created=$_.CreationDate.ToUniversalTime().ToString('o')} })
    $identities | ConvertTo-Json | Set-Content -LiteralPath $identityFile
    $p.Id | Set-Content -LiteralPath (Join-Path $state "$Name.pid")
    Write-Host "$Name started; process identity saved."

}

Write-Host "Umbra - local start"

# --- Tor -----------------------------------------------------------------
$torUp = (Test-NetConnection 127.0.0.1 -Port 9050 -WarningAction SilentlyContinue).TcpTestSucceeded
if ($torUp) {
    Write-Host "  tor     already listening on 9050"
} elseif (Test-Path (Join-Path $tor "tor\tor.exe")) {
    if (Test-Path (Join-Path $tor "tor.log")) { Move-Item (Join-Path $tor "tor.log") (Join-Path $tor "tor.log.prev") -Force }
    $t = Start-Process -FilePath (Join-Path $tor "tor\tor.exe") -ArgumentList "-f", (Join-Path $tor "torrc") -WorkingDirectory $tor -PassThru -WindowStyle Hidden
    $t.Id | Out-File (Join-Path $tor "tor.pid") -Encoding ascii
    Write-Host "  tor     starting (pid $($t.Id)) - waiting for bootstrap" -NoNewline
    $deadline = (Get-Date).AddSeconds(90)
    while ((Get-Date) -lt $deadline) {
        if ((Test-Path (Join-Path $tor "tor.log")) -and (Select-String -Path (Join-Path $tor "tor.log") -Pattern "Bootstrapped 100%" -Quiet)) { break }
        Start-Sleep -Seconds 2; Write-Host "." -NoNewline
    }
    Write-Host ""
    if (-not (Select-String -LiteralPath (Join-Path $tor 'tor.log') -Pattern 'Bootstrapped 100%' -Quiet)) { throw 'Tor did not finish bootstrap. Read the Tor log before starting a crawl.' }
} else {
    throw "No Tor daemon found at $tor and nothing on port 9050 - .onion crawling will fail. Install the Tor Expert Bundle there, or configure Tor Browser's SOCKS port (usually 9150)."
}

# --- API + GUI -----------------------------------------------------------
$listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($listener) {
    $existingHealth = Invoke-RestMethod "http://127.0.0.1:$Port/health" -TimeoutSec 3
    if ($existingHealth.status -ne 'ok' -or -not $existingHealth.version -or $existingHealth.preview) { throw "Port $Port is occupied by another service or a preview." }
    Write-Host "Existing Umbra server responds on port $Port."
} else {
    Start-Detached "serve" $py @("-m", "umbra", "serve", "--host", "127.0.0.1", "--port", "$Port") $root
}
$deadline = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $deadline) {
    try { Invoke-RestMethod "http://127.0.0.1:$Port/health" -TimeoutSec 2 | Out-Null; break } catch { Start-Sleep -Milliseconds 800 }
}

try { Invoke-RestMethod "http://127.0.0.1:$Port/health" -TimeoutSec 3 | Out-Null } catch { throw "API did not start. See $state\serve.log" }

# --- Worker --------------------------------------------------------------
if ($NoWorker) {
    Write-Host "  worker  skipped (-NoWorker)"
} else {
    Start-Detached "worker" $py @("-m", "umbra", "worker", "--interval", "$IntervalSeconds") $root
}

Write-Host ""
Write-Host "  GUI:      http://localhost:$Port/"
Write-Host "  database: $state\umbra.db"
Write-Host "  stop:     .\stop-local.ps1"
