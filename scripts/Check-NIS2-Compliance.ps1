[CmdletBinding()]
param(
  [switch]$AppOnly,
  [string]$TenantId,
  [string]$ClientId,
  [string]$ClientSecret,
  [string]$CertificateThumbprint,
  [string]$OutputPath = "./out"
)

function Write-Section($text) { Write-Host "`n=== $text ===" -ForegroundColor Cyan }

function Ensure-GraphModules {
  $required = @(
    'Microsoft.Graph','Microsoft.Graph.Identity.SignIns','Microsoft.Graph.DirectoryObjects',
    'Microsoft.Graph.DirectoryManagement','Microsoft.Graph.Users','Microsoft.Graph.Policy',
    'Microsoft.Graph.Reports','Microsoft.Graph.RoleManagement'
  )
  foreach ($m in $required) {
    if (-not (Get-Module -ListAvailable -Name $m)) {
      Write-Host "Installing module $m ..." -ForegroundColor Yellow
      try { Install-Module $m -Scope CurrentUser -Force -ErrorAction Stop } catch { throw $_ }
    }
    Import-Module $m -ErrorAction Stop | Out-Null
  }
}

function Connect-GraphSafe {
  if ($AppOnly) {
    if (-not $TenantId -or -not $ClientId -or (-not $ClientSecret -and -not $CertificateThumbprint)) {
      throw "For App-Only, provide TenantId, ClientId and either ClientSecret or CertificateThumbprint."
    }
    if ($ClientSecret) {
      $sec = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
      Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -ClientSecret $sec -NoWelcome | Out-Null
    } elseif ($CertificateThumbprint) {
      Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome | Out-Null
    }
  } else {
    $scopes = @(
      'Policy.Read.All','Directory.Read.All','RoleManagement.Read.Directory',
      'AuditLog.Read.All','UserAuthenticationMethod.Read.All','IdentityRiskyUser.Read.All'
    )
    Connect-MgGraph -Scopes $scopes -NoWelcome | Out-Null
  }
  $ctx = Get-MgContext
  Write-Host "Connected to tenant: $($ctx.TenantId) as $($ctx.Account)" -ForegroundColor Green
}

function New-OutputDir($path) { if (-not (Test-Path $path)) { New-Item -ItemType Directory -Path $path | Out-Null } }

function Get-TenantBasics {
  try { return Get-MgOrganization -ErrorAction Stop | Select-Object Id, DisplayName, VerifiedDomains } catch { return $null }
}

function Test-SecurityDefaults {
  $result = [ordered]@{ Enabled = $null; Details = $null }
  try {
    $sd = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop
    $result.Enabled = $sd.IsEnabled
    $result.Details = if ($sd.IsEnabled) { 'Security defaults are enabled (baseline safeguards active).' } else { 'Security defaults are disabled.' }
  } catch { $result.Details = "Not retrievable: $($_.Exception.Message)" }
  return $result
}

function Get-CAPolicies { try { return Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop } catch { return @() } }

function Test-CA-LegacyBlock($policies) {
  $result = [ordered]@{ Compliant = $false; PolicyId = $null; Name = $null; Details = $null }
  if (-not $policies) { $result.Details = 'No CA policies found'; return $result }
  $hit = $policies | Where-Object {
    $_.State -eq 'enabled' -and $_.Conditions.ClientAppTypes -contains 'other' -and (
      ($_.GrantControls.BuiltInControls -contains 'block') -or ($_.GrantControls.BuiltInControls -contains 'Block')
    )
  } | Select-Object -First 1
  if ($hit) {
    $result.Compliant = $true; $result.PolicyId = $hit.Id; $result.Name = $hit.DisplayName
    $result.Details = 'Legacy authentication is blocked by CA policy.'
  } else {
    $result.Details = 'No active CA policy found that blocks legacy clients.'
  }
  return $result
}

function Test-CA-AdminMFA($policies) {
  $result = [ordered]@{ Compliant = $false; PolicyId = $null; Name = $null; Details = $null }
  if (-not $policies) { $result.Details = 'No CA policies found'; return $result }
  $hit = $policies | Where-Object {
    $_.State -eq 'enabled' -and (
      ($_.GrantControls.BuiltInControls -contains 'mfa') -or ($_.GrantControls.BuiltInControls -contains 'RequireMultiFactorAuthentication') -or $_.AuthenticationStrength -ne $null
    ) -and (
      $_.Conditions.Users -and ($_.Conditions.Users.IncludeRoles -and $_.Conditions.Users.IncludeRoles.Count -gt 0)
    )
  } | Select-Object -First 1
  if ($hit) {
    $result.Compliant = $true; $result.PolicyId = $hit.Id; $result.Name = $hit.DisplayName
    $result.Details = 'Administrator roles are explicitly required to use MFA via CA.'
  } else {
    $result.Details = 'No active CA policy found that explicitly requires MFA for administrator roles.'
  }
  return $result
}

function Test-CA-HighRiskMFA($policies) {
  $result = [ordered]@{ Compliant = $false; PolicyId = $null; Name = $null; Details = $null }
  if (-not $policies) { $result.Details = 'No CA policies found'; return $result }
  $hit = $policies | Where-Object {
    $_.State -eq 'enabled' -and (
      ($_.GrantControls.BuiltInControls -contains 'mfa') -or $_.AuthenticationStrength -ne $null
    ) -and (
      $_.Conditions.SignInRiskLevels -and ($_.Conditions.SignInRiskLevels -contains 'high')
    )
  } | Select-Object -First 1
  if ($hit) {
    $result.Compliant = $true; $result.PolicyId = $hit.Id; $result.Name = $hit.DisplayName
    $result.Details = 'High sign-in risk requires MFA (CA).'
  } else {
    $result.Details = 'No active CA policy found that enforces MFA on high sign-in risk.'
  }
  return $result
}

function Get-PrivilegedRoleMembers {
  $privRoles = @(
    'Global Administrator','Privileged Role Administrator','Security Administrator',
    'Exchange Administrator','SharePoint Administrator','Teams Administrator'
  )
  $members = @()
  try {
    $defs = Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop | Where-Object { $privRoles -contains $_.DisplayName }
    foreach ($def in $defs) {
      $assignments = Get-MgRoleManagementDirectoryRoleAssignment -All -Filter "roleDefinitionId eq '$($def.Id)'" -ErrorAction SilentlyContinue
      foreach ($a in $assignments) { $members += [pscustomobject]@{ Role = $def.DisplayName; PrincipalId = $a.PrincipalId } }
    }
  } catch {}
  $result = @()
  foreach ($m in $members) {
    try {
      $u = Get-MgUser -UserId $m.PrincipalId -Property Id,DisplayName,UserPrincipalName,UserType -ErrorAction Stop
      $result += [pscustomobject]@{ Role=$m.Role; User=$u.DisplayName; UPN=$u.UserPrincipalName; UserId=$u.Id; UserType=$u.UserType }
    } catch {}
  }
  return $result
}

function Test-LegacySignIns {
  $result = [ordered]@{ Found = $null; Sample = @(); Details = $null }
  try {
    $from = (Get-Date).ToUniversalTime().AddDays(-7).ToString('s') + 'Z'
    $logs = Get-MgAuditLogSignIn -Filter "createdDateTime ge $from and clientAppUsed eq 'Other clients'" -Top 10 -ErrorAction Stop
    if ($logs -and $logs.Count -gt 0) {
      $result.Found = $true
      $result.Sample = $logs | Select-Object CreatedDateTime, UserDisplayName, UserPrincipalName, ClientAppUsed
      $result.Details = 'Legacy sign-ins detected in the last 7 days.'
    } else {
      $result.Found = $false
      $result.Details = 'No legacy sign-ins in the last 7 days (sample).'
    }
  } catch {
    $result.Details = "Sign-in logs not retrievable or permission missing: $($_.Exception.Message)"
  }
  return $result
}

function Test-GuestPolicies {
  $result = [ordered]@{ RestrictiveInvitations=$null; Details=@(); Authorization=@{} }
  try {
    $auth = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
    $result.Authorization = $auth | Select-Object Id, DisplayName, Description, AllowedToSignUpEmailBasedSubscriptions, AllowEmailVerifiedUsersToJoinOrganization, DefaultUserRolePermissions
    if ($auth.AllowInvitesFrom) {
      $inv = $auth.AllowInvitesFrom # none | adminsAndGuestInviters | adminsGuestInvitersAndAllMembers | everyone
      $result.RestrictiveInvitations = ($inv -ne 'everyone')
      $result.Details += "AllowInvitesFrom = $inv"
    }
    if ($auth.AllowedToSignUpEmailBasedSubscriptions -eq $true) {
      $result.Details += 'Email-based self-service sign-up is allowed (recommended: disable).'
    }
  } catch {
    $result.Details += "AuthorizationPolicy not retrievable: $($_.Exception.Message)"
  }
  try {
    $dirSettings = Get-MgDirectorySetting -All -ErrorAction Stop | Where-Object { $_.DisplayName -like '*External collaboration settings*' -or $_.TemplateId -ne $null }
    if ($dirSettings) {
      foreach ($s in $dirSettings) {
        if ($s.Values) {
          foreach ($v in $s.Values) {
            if ($v.Name -match 'AllowToAddGuests' -and $v.Value -ne 'False') {
              $result.Details += 'Adding guests is broadly allowed (review).'
            }
          }
        }
      }
    }
  } catch { $result.Details += 'DirectorySettings not retrievable.' }
  return $result
}

function Test-PIM {
  $out = [ordered]@{ UsingPIM=$false; PermanentPrivilegedAssignments=0; Policies=@(); Details=@() }
  try {
    $eligible = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ErrorAction Stop
    if ($eligible -and $eligible.Count -gt 0) { $out.UsingPIM = $true }
  } catch { $out.Details += 'PIM eligibility schedules not retrievable.' }
  try {
    $active = Get-MgRoleManagementDirectoryRoleAssignmentSchedule -All -ErrorAction Stop
    if ($active) {
      $perm = $active | Where-Object { $_.ScheduleInfo.Expiration -eq $null -or $_.ScheduleInfo.Expiration.Type -eq 'noExpiration' }
      $out.PermanentPrivilegedAssignments = ($perm | Measure-Object).Count
    }
  } catch { $out.Details += 'PIM assignment schedules not retrievable.' }
  try {
    $pols = Get-MgPolicyRoleManagementPolicy -Filter "scopeType eq 'Directory'" -ErrorAction Stop
    foreach ($p in $pols) {
      $rules = @()
      try { $rules = Get-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $p.Id -All -ErrorAction Stop } catch {}
      $summary = [ordered]@{ Id=$p.Id; DisplayName=$p.DisplayName; MfaOnActivation=$null; JustificationRequired=$null; TicketingRequired=$null }
      foreach ($r in $rules) {
        if ($r.'@odata.type' -match 'mfaOnRoleActivationRule') { $summary.MfaOnActivation = $r.Enabled }
        if ($r.'@odata.type' -match 'justificationRule') { $summary.JustificationRequired = $r.IsEnabled }
        if ($r.'@odata.type' -match 'ticketingRule') { $summary.TicketingRequired = $r.IsEnabled }
      }
      $out.Policies += $summary
    }
  } catch { $out.Details += 'Role management policies not retrievable.' }
  return $out
}

try {
  Ensure-GraphModules
  Connect-GraphSafe
  New-OutputDir -path $OutputPath

  $report = [ordered]@{}

  Write-Section 'Tenant'
  $tenant = Get-TenantBasics
  $report.Tenant = $tenant
  $tenant | Format-List | Out-Host

  Write-Section 'Security Defaults'
  $secDefaults = Test-SecurityDefaults
  $report.SecurityDefaults = $secDefaults
  $secDefaults | Format-List | Out-Host

  Write-Section 'Conditional Access'
  $policies = Get-CAPolicies
  $caLegacy  = Test-CA-LegacyBlock -policies $policies
  $caAdminMfa = Test-CA-AdminMFA -policies $policies
  $caHighRisk = Test-CA-HighRiskMFA -policies $policies
  $report.ConditionalAccess = [ordered]@{
    LegacyBlock=$caLegacy; AdminMFA=$caAdminMfa; HighRiskMFA=$caHighRisk; PolicyCount=($policies|Measure-Object).Count
  }

  Write-Section 'Privileged Roles'
  $privMembers = Get-PrivilegedRoleMembers
  $report.PrivilegedRoles = [ordered]@{ Members=$privMembers; Count=($privMembers|Measure-Object).Count }
  $privMembers | Format-Table -AutoSize | Out-Host

  Write-Section 'Legacy Sign-Ins (7 days, sample)'
  $legacySigns = Test-LegacySignIns
  $report.LegacySignIns = $legacySigns
  $legacySigns | Format-List | Out-Host

  Write-Section 'Guest/External Collaboration'
  $guest = Test-GuestPolicies
  $report.Guests = $guest
  $guest | Format-List | Out-Host

  Write-Section 'PIM (Privileged Identity Management)'
  $pim = Test-PIM
  $report.PIM = $pim
  $pim | Format-List | Out-Host

  # Compliance Summary
  $criticalFailures = @()
  if (-not $secDefaults.Enabled -and -not $caLegacy.Compliant) { $criticalFailures += 'Legacy authentication is not blocked (neither Security Defaults nor CA).' }
  if (-not $caAdminMfa.Compliant) { $criticalFailures += 'No CA policy found that enforces MFA for admin roles.' }

  $report.Summary = [ordered]@{
    Timestamp = (Get-Date).ToString('s')
    CriticalFindings = $criticalFailures
    Passed = ($criticalFailures.Count -eq 0)
  }

  # Write JSON
  $jsonPath = Join-Path $OutputPath 'nis2_readiness.json'
  $report | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonPath -Encoding UTF8
  # Write Markdown
  $md = @()
  $md += "# NIS2 / DORA Readiness – Entra ID"
  $md += "`n**Generated:** $(Get-Date)"
  $md += "`n`n## Summary"
  $md += "`n- **Passed:** $($report.Summary.Passed)"
  if ($criticalFailures.Count -gt 0) {
    $md += "`n- **Critical gaps:**"
    foreach ($f in $criticalFailures) { $md += "  - $f" }
  } else {
    $md += "`n- No critical gaps detected."
  }
  $md += "`n`n## Details"
  $md += "`n### Security Defaults`n- Enabled: $($secDefaults.Enabled)`n- $($secDefaults.Details)"
  $md += "`n`n### Conditional Access"
  $md += "`n- Legacy block: $($caLegacy.Compliant) (Policy: $($caLegacy.Name))"
  $md += "`n- Admin MFA (role-based): $($caAdminMfa.Compliant) (Policy: $($caAdminMfa.Name))"
  $md += "`n- High risk -> MFA: $($caHighRisk.Compliant) (Policy: $($caHighRisk.Name))"
  $md += "`n`n### Privileged Roles"
  $md += "`n- Total privileged members: $($report.PrivilegedRoles.Count)"
  foreach ($m in $privMembers) { $md += "  - $($m.Role): $($m.User) ($($m.UPN))" }
  $md += "`n`n### Legacy Sign-ins (7 days)`n- Found: $($legacySigns.Found)`n- Note: $($legacySigns.Details)"
  $md += "`n`n### Guests / External Collaboration"
  foreach ($d in $guest.Details) { $md += "- $d" }
  $md += "`n`n### PIM"
  $md += "`n- Using PIM: $($pim.UsingPIM)"
  $md += "`n- Permanent privileged assignments: $($pim.PermanentPrivilegedAssignments)"
  foreach ($pol in $pim.Policies) { $md += "  - Policy: $($pol.DisplayName) | MFA on activation: $($pol.MfaOnActivation) | Justification: $($pol.JustificationRequired) | Ticketing: $($pol.TicketingRequired)" }

  $mdPath = Join-Path $OutputPath 'nis2_readiness.md'
  $md -join "`n" | Out-File -FilePath $mdPath -Encoding UTF8

  Write-Host "`nResults written to: $jsonPath, $mdPath" -ForegroundColor Green
  if ($criticalFailures.Count -gt 0) { exit 2 } else { exit 0 }

} catch {
  Write-Error $_
  exit 1
}
