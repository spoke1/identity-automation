# NIS2 / DORA Readiness Check for Microsoft Entra ID

This repository provides a PowerShell script to assess selected Microsoft Entra ID / Microsoft 365 configurations against practical Zero Trust controls aligned to NIS2/DORA expectations. It does **not** constitute a compliance determination. Instead, it produces a repeatable readiness snapshot to support your risk and gap analysis.

## Scope of Checks

- Multi-factor authentication (MFA) required for **administrator roles** via Conditional Access
- **Conditional Access** baseline presence
- **Legacy authentication** blocked (or Security Defaults enabled)
- **Guest and external collaboration** restrictions
- **Privileged Identity Management (PIM)** usage and activation policies

Results are written as **JSON** and **Markdown**. The script exits with a **non‑zero** code when critical controls are missing to allow CI/CD gating.

---

## Requirements

- PowerShell 7.x (recommended) or Windows PowerShell 5.1
- Microsoft Graph PowerShell SDK (the script installs/imports required modules if missing)
- Permissions depending on mode:

### Delegated (interactive)
- `Policy.Read.All`
- `Directory.Read.All`
- `RoleManagement.Read.Directory`
- `AuditLog.Read.All` (optional, recommended for legacy sign-in sampling)
- `UserAuthenticationMethod.Read.All` (optional headroom for future checks)

### App-Only (recommended for CI/CD)
- Same as above, granted as **Application** permissions in the Azure app registration
- Admin consent must be granted

> The legacy sign-in sampling uses sign-in logs for the last 7 days if `AuditLog.Read.All` is available.

---

## Usage

### Local (interactive delegated)
```pwsh
# from repository root
pwsh -File ./scripts/NIS2-Entra-Readiness.ps1 -OutputPath ./out
