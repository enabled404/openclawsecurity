# Security Policy

OpenClawAudit is a **defensive security tool** designed to help users identify vulnerabilities in their own installations. This document describes our security policy and how to report security issues.

## Reporting a Vulnerability

### In OpenClawAudit Itself

If you discover a security vulnerability in the OpenClawAudit tool itself:

1.  **Do not open a public GitHub issue.**
2.  Email full details to security@openclaw.ai (or equivalent if self-hosted context).
3.  Include reproduction steps and potential impact.

We will acknowledge receipt within 48 hours and provide a timeline for fixes.

### In Systems OpenClawAudit Checks

If you discover new attack vectors against OpenClaw installations that OpenClawAudit should detect:

1.  Open a feature request issue on GitHub.
2.  Describe the attack vector conceptually (do not share exploits for live systems).
3.  Suggest how we can detect it defensively.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 3.x     | :white_check_mark: |
| 2.x     | :x:                |
| 1.x     | :x:                |

## Responsible Use

When using OpenClawAudit:

*   **Only audit systems you own or have explicit permission to test.**
*   The tool is for defensive hardening, not offensive operations.
*   We are not responsible for any damage caused by misuse of this tool.

## Threat Model

OpenClawAudit assumes:

*   The user running the tool has legitimate access to the server.
*   The goal is to harden the environment against external attackers.
*   The tool itself is trustworthy (verify hashes/signatures if available).

## Out of Scope

*   Vulnerabilities in third-party dependencies (unless directly reachable).
*   Physical security of the server.
*   Social engineering attacks.

## Security Updates

Security updates will be released as new versions (e.g., v3.0.1). Users are encouraged to always run the latest version before performing an audit.

---

### Classification of Issues

We classify issues as:

*   **Critical**: RCE, Privilege Escalation in the tool itself
*   **High**: Security bypass in the tool, or failure to detect critical known vulnerabilities
*   **Medium**: False negatives for moderate risks
*   **Low**: UX issues, false positives

---

**Thank you for helping keep the OpenClaw ecosystem secure!**

## Scope

### In Scope

- Vulnerabilities in the OpenClawAudit script itself
- False negatives (security issues not detected)
- False positives (incorrect security warnings)
- New attack vectors to detect

### Out of Scope

- Vulnerabilities in third-party dependencies (report upstream)
- Social engineering attacks
- Physical security
- Issues in systems OpenClawAudit checks (report to those projects)

## Contact

For security issues, contact the maintainers through:
- GitHub Security Advisories (preferred)
- Direct email to repository maintainers

Thank you for helping keep the community secure!
