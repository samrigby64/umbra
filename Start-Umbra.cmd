@echo off
powershell.exe -NoProfile -File "%~dp0run-local.ps1" -NoWorker
if errorlevel 1 (
  pause
  exit /b 1
)
start "" "http://localhost:8000/"
