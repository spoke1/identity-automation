<#
.SYNOPSIS
    Collects Intune Autopilot / ESP troubleshooting logs and system info into a single ZIP.

.DESCRIPTION
    Gathers common log locations (IME, Autopilot, Provisioning, OOBE, CloudExperienceHost, Panther),
    exports key Event Logs (DM-EDP, Autopilot, AAD Join, DeviceManagement), captures dsregcmd/ipconfig,
    and compresses everything to a timestamped ZIP on the current user's Desktop.

.NOTES
    Author : Ramón Lotz
    Repo   : https://github.com/spoke1/identity-automation
    Version: 1.0

.REQUIREMENTS
    - Run as Administrator (recommended for full log access).
#>

[CmdletBinding()]
param(
    [string]$OutRoot = "$env:ProgramData\IdentityAutomation\ESPCollector"
)

function Test-Admin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

$timeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$sessionDir = Join-Path $OutRoot "Collect_$timeStamp"
$null = New-Item -ItemType Directory -Force -Path $sessionDir

Write-Host "▶ Collecting Intune/Autopilot logs into: $sessionDir"

# --- helper: safe copy ---
function Copy-IfExists {
    param([string]$Path,[string]$Dest)
    try {
        if (Test-Path $Path) {
            New-Item -ItemType Directory -Force -Path $Dest | Out-Null
            Copy-Item -Path $Path -Destination $Dest -Recurse -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Warning "Failed to copy $Path : $($_.Exception.Message)"
    }
}

# --- common log locations ---
$targets = @(
    @{Src="C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\*"; Dest="IME"},
    @{Src="C:\Windows\Logs\Autopilot\*"; Dest="Autopilot"},
    @{Src="C:\Windows\Provisioning\Logs\*"; Dest="Provisioning"},
    @{Src="C:\Windows\Logs\CloudExperienceHost\*"; Dest="CloudExperienceHost"},
    @{Src="C:\Windows\Panther\*"; Dest="Panther"},
    @{Src="C:\Windows\Logs\MoSetup\*"; Dest="MoSetup"},
    @{Src="C:\Windows\System32\Sysprep\Panther\*"; Dest="SysprepPanther"},
    @{Src="C:\Windows\Temp\*ESP*"; Dest="TempESP"},
    @{Src="C:\Windows\CCM\Logs\*"; Dest="ConfigMgr"} # falls SCCM-Client vorhanden
)

foreach ($t in $targets) {
    Copy-IfExists -Path $t.Src -Dest (Join-Path $sessionDir $t.Dest)
}

# --- Event Logs export (.evtx) ---
$evDir = Join-Path $sessionDir "EventLogs"
New-Item -ItemType Directory -Force -Path $evDir | Out-Null

$eventLogs = @(
    "Microsoft-Windows-User Device Registration/Admin",
    "Microsoft-Windows-ModernDeployment-Diagnostics-Provider/Autopilot",
    "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
    "Microsoft-Windows-AAD/Operational",
    "Microsoft-Windows-CloudExperienceHost/Operational",
    "Application",
    "System"
)

foreach ($log in $eventLogs) {
    $safeName = ($log -replace '[\\/\s]', '_')
    $evtxPath = Join-Path $evDir "$safeName.evtx"
    try {
        wevtutil epl "$log" "$evtxPath"
    } catch {
        Write-Warning "Could not export event log '$log' : $($_.Exception.Message)"
    }
}

# --- Diagnostic commands output ---
$diagDir = Join-Path $sessionDir "Diagnostics"
New-Item -ItemType Directory -Force -Path $diagDir | Out-Null

# dsregcmd status (AAD Join)
try { dsregcmd /status > (Join-Path $diagDir "dsregcmd_status.txt") } catch {}
# Network + route info
ipconfig /all > (Join-Path $diagDir "ipconfig_all.txt") 2>$null
route print > (Join-Path $diagDir "route_print.txt") 2>$null
# Intune IME service status
Get-Service -Name IntuneManagementExtension,DeviceManagementEnrollmentService,DeviceAssociationService -ErrorAction SilentlyContinue `
    | Format-List * | Out-File -FilePath (Join-Path $diagDir "services_status.txt") -Encoding UTF8
# Basic device info
Get-ComputerInfo | Out-File -FilePath (Join-Path $diagDir "computerinfo.txt") -Encoding UTF8

# --- Registry snippets (Enrollment, Autopilot) ---
$regDir = Join-Path $sessionDir "Registry"
New-Item -ItemType Directory -Force -Path $regDir | Out-Null

$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Provisioning",
    "HKLM:\SOFTWARE\Microsoft\Windows\Autopilot",
    "HKLM:\SOFTWARE\Microsoft\Enrollments",
    "HKLM:\SOFTWARE\Microsoft\PolicyManager"
)

foreach ($r in $regPaths) {
    $name = ($r -replace '[:\\/]','_') + ".txt"
    try {
        reg query ($r -replace "HKLM:","HKLM") /s > (Join-Path $regDir $name) 2>$null
    } catch {}
}

# --- ZIP it ---
$zipName = "ESP_Collect_$($env:COMPUTERNAME)_$timeStamp.zip"
$desktop = [Environment]::GetFolderPath('Desktop')
$zipPath = Join-Path $desktop $zipName

if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path $sessionDir\* -DestinationPath $zipPath -Force

Write-Host ""
if (Test-Admin) {
    Write-Host "Collection complete."
} else {
    Write-Warning "Collection finished, but not all paths may have been captured (not running as Admin)."
}
Write-Host "ZIP: $zipPath"
