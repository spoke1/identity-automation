<#
.SYNOPSIS
    Lists all Global Administrators in Microsoft Entra ID.

.DESCRIPTION
    This script connects to Microsoft Graph and retrieves all users
    with the Global Administrator role. The results are exported
    to a CSV file for easy auditing and reporting.

.NOTES
    Author: Ramón Lotz
    Repo: https://github.com/spoke1/identity-automation
    Version: 1.0
#>

# Connect to Microsoft Graph
Connect-MgGraph -Scopes "RoleManagement.Read.Directory", "Directory.Read.All"

# Select API version
Select-MgProfile -Name beta

# Get Global Admins
$globalAdmins = Get-MgRoleManagementDirectoryRoleAssignment `
    | Where-Object { $_.RoleDefinitionId -eq (Get-MgDirectoryRole | Where-Object DisplayName -eq "Global Administrator").Id }

# Expand user details
$results = foreach ($admin in $globalAdmins) {
    $user = Get-MgUser -UserId $admin.PrincipalId
    [PSCustomObject]@{
        DisplayName = $user.DisplayName
        UserPrincipalName = $user.UserPrincipalName
        Id = $user.Id
    }
}

# Export to CSV
$results | Export-Csv -Path ".\GlobalAdmins.csv" -NoTypeInformation -Encoding UTF8

Write-Host "Export completed. File saved as GlobalAdmins.csv"
