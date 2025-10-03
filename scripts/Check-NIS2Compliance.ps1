<#
.SYNOPSIS
    Basic NIS2/DORA compliance readiness check for Microsoft Entra ID tenants.

.DESCRIPTION
    This script checks selected Entra ID / M365 configurations related to NIS2/DORA.
    It does NOT guarantee compliance, but highlights key Zero Trust controls:
    - MFA for admins
    - Conditional Access baseline
    - Legacy authentication disabled
    - Guest account restrictions
    - Privileged roles protected by PIM

.REQUIREMENTS
    - Microsoft Graph PowerShell SDK
    - Permissions: Directory.Read.All, Policy.Read.All, RoleManagement.Read.Directory

.NOTES
    Author: Ramón Lotz
    Repo  : https://github.com/spoke1/identity-automation
    Version: 1.0
#>

$report = [System.Collections.Generic.List[Object]]::new()

function Add-Check {
    param($Name, $Result, $Details)
    $report.Add([PSCustomObject]@{
        Check   = $Name
        Result  = $Result
        Details = $Details
    })
}

Write-Host "▶ Connecting to Microsoft Graph..."
Connect-MgGraph -Scopes "Directory.Read.All","Policy.Read.All","RoleManagement.Read.Directory"
Select-MgProfile -Name beta

# --- 1. MFA enforced for admins ---
Write-Host "Checking MFA enforcement..."
$policies = Get-MgIdentityConditionalAccessPolicy -All
$gaRole = (Get-MgDirectoryRole | Where-Object DisplayName -eq "Global Administrator")
$gaAssignments = Get-MgRoleManagementDirectoryRoleAssignment | Where-Object RoleDefinitionId -eq $gaRole.Id

$mfaForAdmins = $false
if ($policies) {
    foreach ($p in $policies) {
        if ($p.GrantControls.BuiltInControls -contains "mfa") {
            $mfaForAdmins = $true
            break
        }
    }
}
Add-Check "MFA enforced for Admins" ($mfaForAdmins ? "PASS" : "FAIL") ("Total Global Admins: " + $gaAssignments.Count)

# --- 2. Legacy Authentication blocked ---
Write-Host "Checking legacy auth..."
$legacyBlocked = $false
if ($policies) {
    foreach ($p in $policies) {
        if ($p.Conditions.ClientAppTypes -contains "other") {
            if ($p.State -eq "enabled") {
                $legacyBlocked = $true
                break
            }
        }
    }
}
Add-Check "Legacy Authentication blocked" ($legacyBlocked ? "PASS" : "FAIL") ""

# --- 3. Guest restrictions ---
Write-Host "Checking guest accounts..."
$guests = Get-MgUser -Filter "userType eq 'Guest'" -ConsistencyLevel eventual -CountVariable total -All
$guestCount = $total
$guestPolicy = Get-MgPolicyAuthorizationPolicy
$guestAccess = $guestPolicy.AllowInvitesFrom
$guestRestricted = $guestAccess -eq "adminsAndGuestInviters"
Add-Check "Guest restrictions" ($guestRestricted ? "PASS" : "FAIL") ("Guests: $guestCount; Policy: $guestAccess")

# --- 4. Privileged Identity Mgmt (PIM) enabled for admins ---
Write-Host "Checking PIM for admins..."
$pimRoles = Get-MgPrivilegedAccessRoleSetting -ProviderId "aadRoles" -ErrorAction SilentlyContinue
$pimEnabled = $pimRoles.Count -gt 0
Add-Check "Privileged Identity Mgmt active" ($pimEnabled ? "PASS" : "FAIL") ("PIM Roles found: $($pimRoles.Count)")

# --- 5. Conditional Access baseline policies exist ---
Write-Host "Checking CA baseline..."
$caBaseline = ($policies.Count -gt 0)
Add-Check "Conditional Access Policies exist" ($caBaseline ? "PASS" : "FAIL") ("Policies: $($policies.Count)")

# --- Output ---
$report | Format-Table -AutoSize

$outFile = ".\NIS2_ComplianceCheck_$(Get-Date -Format yyyyMMdd_HHmmss).csv"
$report | Export-Csv -Path $outFile -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "Check complete. Report saved to $outFile"
