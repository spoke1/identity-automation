# Conditional Access Export

Exports all Conditional Access policies to JSON and CSV, plus a Markdown summary.

## Requirements
- Microsoft Graph PowerShell SDK
- Scopes: Policy.Read.All, Directory.Read.All

## Installation
Install-Module Microsoft.Graph -Scope CurrentUser
Connect-MgGraph -Scopes "Policy.Read.All Directory.Read.All"
./scripts/Export-ConditionalAccessPolicies.ps1 -OutDir ".\output\ca-export"
