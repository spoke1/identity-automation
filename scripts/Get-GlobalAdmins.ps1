<#
.SYNOPSIS
  Export all Global Administrators (Microsoft Entra ID) to CSV.

.DESCRIPTION
  Uses Microsoft Graph PowerShell to find the Global Administrator role by its immutable template ID,
  enumerate all active members, optionally expand role-assignable groups to user identities, and export to CSV.

.PARAMETER OutputPath
  Folder to write the CSV into. Defaults to current directory.

.PARAMETER ExpandGroupMembers
  When set, expands role-assignable groups so that users inherited via group are listed individually.

.EXAMPLE
  .\Export-GlobalAdmins.ps1 -OutputPath "C:\Reports" -ExpandGroupMembers
#>

[CmdletBinding()]
param(
  [string]$OutputPath = (Get-Location).Path,
  [switch]$ExpandGroupMembers
)

# ------- Constants -------
# Immutable template ID for "Global Administrator" (a.k.a. Company Administrator)
# Source: Microsoft Entra built-in roles reference
$GlobalAdminTemplateId = '62e90394-69f5-4237-9190-012177145e10'

# ------- Connect to Microsoft Graph (least privilege for this task) -------
Import-Module Microsoft.Graph -ErrorAction Stop

# Request only what we need: role assignments + basic user read
$scopes = @('RoleManagement.Read.Directory','User.Read.All')
Write-Host "Connecting to Microsoft Graph with scopes: $($scopes -join ', ' ) ..."
Connect-MgGraph -Scopes $scopes | Out-Null
Select-MgProfile -Name 'v1.0'

# ------- Resolve tenant info for file naming -------
$org = Get-MgOrganization -ErrorAction Stop
$tenantName = ($org.DisplayName -replace '[^a-zA-Z0-9\- ]','').Trim()  # sanitize for file name

# ------- Find the Global Administrator directory role by template ID -------
# Note: Get-MgDirectoryRole returns only "activated" directory roles (ones with assignments).
$gaRole = Get-MgDirectoryRole -Filter "roleTemplateId eq '$GlobalAdminTemplateId'" -ErrorAction SilentlyContinue

if (-not $gaRole) {
  Write-Warning "Global Administrator role is not activated (no assignments found). Exporting an empty CSV with headers."
  $empty = [PSCustomObject]@{
    Tenant              = $tenantName
    RoleDisplayName     = 'Global Administrator'
    AssignmentType      = $null   # Direct | ViaGroup | App | GroupObject
    DisplayName         = $null
    UserPrincipalName   = $null
    ObjectId            = $null
    SourceGroupName     = $null
    SourceGroupObjectId = $null
    AccountEnabled      = $null
    UserType            = $null
  }
  $file = Join-Path $OutputPath ("GlobalAdministrators_{0}_{1}.csv" -f $tenantName, (Get-Date -Format 'yyyyMMdd'))
  $empty | Export-Csv -NoTypeInformation -Path $file
  Write-Host "Export completed: $file"
  return
}

Write-Host "Found role: $($gaRole.DisplayName)  (ID: $($gaRole.Id))"

# ------- Get all members of the Global Administrator role -------
$members = Get-MgDirectoryRoleMember -DirectoryRoleId $gaRole.Id -All

$results = New-Object System.Collections.Generic.List[object]

foreach ($m in $members) {
  $type = $m.AdditionalProperties.'@odata.type'

  switch ($type) {
    # User principals assigned directly
    ('#microsoft.graph.user') {
      $u = Get-MgUser -UserId $m.Id -Property Id,DisplayName,UserPrincipalName,AccountEnabled,UserType -ErrorAction SilentlyContinue
      $results.Add([PSCustomObject]@{
        Tenant              = $tenantName
        RoleDisplayName     = $gaRole.DisplayName
        AssignmentType      = 'Direct'
        DisplayName         = $u.DisplayName
        UserPrincipalName   = $u.UserPrincipalName
        ObjectId            = $u.Id
        SourceGroupName     = $null
        SourceGroupObjectId = $null
        AccountEnabled      = $u.AccountEnabled
        UserType            = $u.UserType
      })
      break
    }

    # Role-assignable group assigned to GA
    ('#microsoft.graph.group') {
      # Always record the group object (for visibility)
      $g = Get-MgGroup -GroupId $m.Id -Property Id,DisplayName,GroupTypes -ErrorAction SilentlyContinue
      $results.Add([PSCustomObject]@{
        Tenant              = $tenantName
        RoleDisplayName     = $gaRole.DisplayName
        AssignmentType      = 'GroupObject'
        DisplayName         = $g.DisplayName
        UserPrincipalName   = $null
        ObjectId            = $g.Id
        SourceGroupName     = $g.DisplayName
        SourceGroupObjectId = $g.Id
        AccountEnabled      = $null
        UserType            = $null
      })

      if ($ExpandGroupMembers.IsPresent) {
        # Expand to actual users who are members of this role-assignable group
        $gMembers = Get-MgGroupMember -GroupId $g.Id -All -ErrorAction SilentlyContinue
        foreach ($gm in $gMembers) {
          if ($gm.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user') {
            $gu = Get-MgUser -UserId $gm.Id -Property Id,DisplayName,UserPrincipalName,AccountEnabled,UserType -ErrorAction SilentlyContinue
            $results.Add([PSCustomObject]@{
              Tenant              = $tenantName
              RoleDisplayName     = $gaRole.DisplayName
              AssignmentType      = 'ViaGroup'
              DisplayName         = $gu.DisplayName
              UserPrincipalName   = $gu.UserPrincipalName
              ObjectId            = $gu.Id
              SourceGroupName     = $g.DisplayName
              SourceGroupObjectId = $g.Id
              AccountEnabled      = $gu.AccountEnabled
              UserType            = $gu.UserType
            })
          }
        }
      }
      break
    }

    # Service principals (apps) assigned to GA (rare, but possible)
    ('#microsoft.graph.servicePrincipal') {
      $sp = Get-MgServicePrincipal -ServicePrincipalId $m.Id -Property Id,DisplayName -ErrorAction SilentlyContinue
      $results.Add([PSCustomObject]@{
        Tenant              = $tenantName
        RoleDisplayName     = $gaRole.DisplayName
        AssignmentType      = 'App'
        DisplayName         = $sp.DisplayName
        UserPrincipalName   = $null
        ObjectId            = $sp.Id
        SourceGroupName     = $null
        SourceGroupObjectId = $null
        AccountEnabled      = $null
        UserType            = 'ServicePrincipal'
      })
      break
    }

    default {
      # Fallback for any other directoryObject types
      $results.Add([PSCustomObject]@{
        Tenant              = $tenantName
        RoleDisplayName     = $gaRole.DisplayName
        AssignmentType      = 'Other'
        DisplayName         = $null
        UserPrincipalName   = $null
        ObjectId            = $m.Id
        SourceGroupName     = $null
        SourceGroupObjectId = $null
        AccountEnabled      = $null
        UserType            = $type
      })
      break
    }
  }
}

# ------- Export CSV -------
$file = Join-Path $OutputPath ("GlobalAdministrators_{0}_{1}.csv" -f $tenantName, (Get-Date -Format 'yyyyMMdd'))
$results | Sort-Object AssignmentType, DisplayName | Export-Csv -NoTypeInformation -Path $file

Write-Host "Export completed: $file"
