# NIS2 / DORA Compliance Readiness Check

This script performs a **basic readiness assessment** of your Microsoft Entra ID tenant 
against common requirements from **NIS2** and **DORA**.  
It highlights whether key Zero Trust controls are configured.

⚠️ **Disclaimer:** This is a **basic readiness tool**, not an official compliance validation.  
Always consult your compliance team and auditors for full assessments.

---

## 🔍 What it checks
- MFA enforced for administrators  
- Legacy authentication blocked  
- Guest account restrictions  
- Privileged Identity Management (PIM) active for admins  
- Conditional Access policies exist  

---

## 📦 Requirements
- Microsoft Graph PowerShell SDK  
- Permissions:  
  - `Directory.Read.All`  
  - `Policy.Read.All`  
  - `RoleManagement.Read.Directory`  

Install module (if not already installed):
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
