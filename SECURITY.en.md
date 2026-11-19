[<img src="https://flagcdn.com/id.svg" width="18" alt="ID"> Indonesia](SECURITY.md) · **<img src="https://flagcdn.com/gb.svg" width="18" alt="EN"> English** · [<img src="https://flagcdn.com/de.svg" width="18" alt="DE"> Deutsch](SECURITY.de.md)

# Security Policy

Thanks for helping keep **Security Audit Kit** secure.

## Supported versions

Security fixes are applied to the latest release and the `main` branch.

| Version | Supported |
|---|---|
| Latest stable release | ✅ |
| `main` | ✅ |
| Older versions | ❌ |

## Reporting a vulnerability

**Do not** open a public issue for a security vulnerability.

Use **GitHub Private Vulnerability Reporting**:

1. Open the **Security** tab of this repo.
2. Click **Report a vulnerability**.
3. Fill in the details: reproduction steps, impact, affected version/commit, and evidence if any.

The report stays private between you and the maintainer until a fix is available.

### What to expect

- **Acknowledgement of receipt:** usually within 3 business days.
- **Initial assessment & triage:** within 7 business days.
- **Fix & disclosure:** coordinated with the reporter; credit given if desired.

## Scope

This toolkit **tests the security of other systems**. The reports meant here are
vulnerabilities **in the kit itself** (e.g. unintended code execution while parsing
output, credential leakage from config/reports, or a defect that makes the kit attack
a target it wasn't asked to).

## Responsible use

This kit is only for testing systems you **own or are authorized to test**. Testing
third-party systems without permission violates the law in many jurisdictions and is
outside this project's purpose. Target credentials always go through environment
variables, not in committed files.
