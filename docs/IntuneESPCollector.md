# Intune ESP / Autopilot Log Collector

Collects Intune/Autopilot logs, event logs, and diagnostics into a single ZIP for troubleshooting.

## Requirements
- Windows PowerShell (Run **as Administrator** recommended)

## Usage
Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File 
.\scripts\Collect-IntuneESPLogs.ps1'
