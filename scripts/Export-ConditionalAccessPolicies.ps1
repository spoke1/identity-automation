<#
.SYNOPSIS
    Exportiert alle Microsoft Entra ID Conditional Access (CA) Policies in JSON + CSV
    und erzeugt eine kompakte Markdown-Übersicht.

.DESCRIPTION
    Verwendet das Microsoft Graph PowerShell SDK.
    - Liest alle CA-Policies
    - Exportiert vollständige Rohdaten als JSON
    - Erstellt flache CSV-Ansicht für Audits
    - Generiert CA-Summary als README-ähnliches Markdown

.REQUIREMENTS
    Install-Module Microsoft.Graph -Scope CurrentUser
    Rollen/Scopes: Policy.Read.All (mind.), Directory.Read.All empfohlen

.NOTES
    Author: Ramón Lotz
    Repo  : https://github.com/spoke1/identity-automation
    Version: 1.0
#>

param(
    [string]$OutDir = ".\output\ca-export"
)

# 1) Connect to Graph
if (-not (Get-Module Microsoft.Graph -ListAvailable)) {
    Write-Host "Installing Microsoft.Graph..." 
    Install-Module Microsoft.Graph -Scope CurrentUser -Force
}
Import-Module Microsoft.Graph

$scopes = @(
    "Policy.Read.All",
    "Directory.Read.All"
)

Write-Host "Connecting to Microsoft Graph..."
Connect-MgGraph -Scopes $scopes | Out-Null
Select-MgProfile -Name beta  # beta nötig für manche CA-Details; bei Bedarf auf v1.0 wechseln

# 2) Output-Verzeichnis vorbereiten
$null = New-Item -ItemType Directory -Force -Path $OutDir
$jsonPath = Join-Path $OutDir "ConditionalAccessPolicies.json"
$csvPath  = Join-Path $OutDir "ConditionalAccessPolicies.csv"
$mdPath   = Join-Path $OutDir "ConditionalAccessPolicies.md"

# 3) Policies abrufen
Write-Host "Fetching Conditional Access policies..."
$policies = Get-MgIdentityConditionalAccessPolicy -All

if (-not $policies) {
    Write-Warning "Keine Policies gefunden oder fehlende Berechtigungen."
    return
}

# 4) JSON Raw-Export
$policies | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8

# 5) CSV (flattened)
$rows = foreach ($p in $policies) {
    # Bedingungen zusammenfassen
    $usersInc = ($p.Conditions.Users.IncludeUsers -join ';')
    $usersExc = ($p.Conditions.Users.ExcludeUsers -join ';')
    $rolesInc = ($p.Conditions.Users.IncludeRoles -join ';')
    $grpsInc  = ($p.Conditions.Users.IncludeGroups -join ';')
    $grpsExc  = ($p.Conditions.Users.ExcludeGroups -join ';')

    $platforms = if ($p.Conditions.Platforms) { ($p.Conditions.Platforms.IncludePlatforms -join ';') } else { "" }
    $locations = if ($p.Conditions.Locations) { ($p.Conditions.Locations.IncludeLocations -join ';') } else { "" }
    $apps      = if ($p.Conditions.Applications) { ($p.Conditions.Applications.IncludeApplications -join ';') } else { "" }
    $clientAppTypes = if ($p.Conditions.ClientAppTypes) { ($p.Conditions.ClientAppTypes -join ';') } else { "" }

    $grantControls = if ($p.GrantControls) { ($p.GrantControls.BuiltInControls -join ';') } else { "" }
    $sessionControls = if ($p.SessionControls) {
        @(
            if ($p.SessionControls.SignInFrequency) { "SignInFrequency=$($p.SessionControls.SignInFrequency.Value)$($p.SessionControls.SignInFrequency.Type)" }
            if ($p.SessionControls.PersistedBrowser) { "PersistedBrowser=$($p.SessionControls.PersistedBrowser.IsEnabled)" }
            if ($p.SessionControls.CloudAppSecurity) { "MCAS=$($p.SessionControls.CloudAppSecurity.CloudAppSecurityType)" }
            if ($p.SessionControls.DisableResilienceDefaults) { "DisableResilience=$($p.SessionControls.DisableResilienceDefaults)" }
        ) -join ';'
    } else { "" }

    [pscustomobject]@{
        DisplayName      = $p.DisplayName
        State            = $p.State
        CreatedDateTime  = $p.CreatedDateTime
        ModifiedDateTime = $p.ModifiedDateTime
        Conditions_Apps  = $apps
        Conditions_Users_IncludeUsers = $usersInc
        Conditions_Users_ExcludeUsers = $usersExc
        Conditions_Users_IncludeGroups = $grpsInc
        Conditions_Users_ExcludeGroups = $grpsExc
        Conditions_Users_IncludeRoles  = $rolesInc
        Conditions_Platforms = $platforms
        Conditions_Locations = $locations
        Conditions_ClientAppTypes = $clientAppTypes
        GrantControls     = $grantControls
        SessionControls   = $sessionControls
    }
}

$rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

# 6) Markdown-Summary
$lines = @("# Conditional Access Policy Export", "", "> Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')", "")
$lines +=
