### 4) NIS2 / DORA Compliance Check
**File:** scripts/Check-NIS2Compliance.ps1
**Purpose:** Quick readiness check (MFA for admins, legacy auth blocked, guest restrictions, PIM active, CA policies present).

**Requirements**
- Microsoft Graph PowerShell SDK  
- Scopes: `Directory.Read.All`, `Policy.Read.All`, `RoleManagement.Read.Directory`

**Run**
Install-Module Microsoft.Graph -Scope CurrentUser
Connect-MgGraph -Scopes "Directory.Read.All Policy.Read.All RoleManagement.Read.Directory"
./scripts/Check-NIS2Compliance.ps1
