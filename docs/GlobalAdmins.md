## Export Global Administrators (Microsoft Entra ID) to CSV

Export a list of **Global Administrators** (a.k.a. Company Administrators) from your tenant to CSV using **Microsoft Graph PowerShell**.

> Uses the role’s immutable template ID `62e90394-69f5-4237-9190-012177145e10` to avoid localization issues.  
> Requires Graph scopes: `RoleManagement.Read.Directory` and `User.Read.All`.

### Prerequisites
- PowerShell 7+ recommended
- Microsoft Graph PowerShell SDK

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
