# Security Policy

Thank you for responsibly reporting security issues affecting Aegis Latent Core. This document explains how to contact the maintainers and what information to include.

Preferred reporting channels

- GitHub Security Advisories (recommended): use the repository Security tab and create an Advisory so sensitive details remain private until fixed.
- Private security report: open a private issue using the `.github/ISSUE_TEMPLATE/security_report.md` template (available in this repo).
- If you are unable to use the above, contact the project maintainers by email at `security@<YOUR_ORG_DOMAIN>` and PGP-encrypt sensitive details. Replace `<YOUR_ORG_DOMAIN>` with the correct organizational contact.

Information to provide

When reporting a vulnerability, please include:

- A short title and severity estimate.
- A concise description of the issue and the impact.
- A step-by-step reproduction (minimum viable PoC) or a proof-of-concept exploit if available.
- Affected versions / environment details (Python, OS, provider adapters, optional extras used).
- Relevant logs, stack traces, or network captures (prefer PGP-encrypted attachments when sensitive).
- Your contact information and preferred encrypted channel (PGP key fingerprint or GitHub handle).

Reporter expectations & timelines

- Acknowledgement: maintainers will acknowledge receipt within 72 hours.
- Triage: initial triage and prioritization within 7 days.
- Remediation: the timeline for a fix depends on severity; maintainers will coordinate a disclosure timeline with the reporter.
- Coordinated disclosure: do not publish exploit details or PoCs publicly until a fix or mitigation is available and a disclosure plan is agreed.

If you are a maintainer

- Add a security contact to repository settings (Security & analysis) and publish a PGP public key for encrypted reports.
- Monitor the Security Advisories and respond promptly; track and close advisories only after verification of fixes.
- Consider CVE assignment for confirmed security issues and coordinate with the reporter on disclosure.

Thank you for helping keep Aegis Latent Core safe. We appreciate responsible disclosure and will work to address issues promptly.
