# Global Admin Audit

Lists all Global Administrators in Microsoft Entra ID and exports results to CSV.

## Requirements
- Microsoft Graph PowerShell SDK
- Scopes: RoleManagement.Read.Directory, Directory.Read.All

## Installation
powershell
Install-Module Microsoft.Graph -Scope CurrentUser
Connect-MgGraph -Scopes "RoleManagement.Read.Directory Directory.Read.All"
./scripts/Get-GlobalAdmins.ps1
