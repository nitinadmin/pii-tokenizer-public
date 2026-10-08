# Security Policy

## Reporting a vulnerability

Please do not disclose security vulnerabilities through public GitHub issues.

Use the repository's private security advisory mechanism (GitHub: **Security → Report a vulnerability**). If that is unavailable, contact the maintainers privately through the contact listed on the repository profile, and ask for a private channel before sending details.

We aim to acknowledge reports within 5 business days.

Include:

- affected component and version
- reproduction steps
- security impact
- suggested mitigation, if known

Please avoid including real PII, credentials, API keys, production documents, or other sensitive material in reports.

## Supported versions

Only the latest release receives security fixes.

## Scope

Security-sensitive areas include:

- raw document ingestion
- file-type and active-content validation
- S3 quarantine and token-vault access
- GuardDuty integration
- PII detection and validation
- LLM boundary handling
- logs and error responses
- frontend handling of token maps

## Known issues

Open findings from the most recent review are tracked in [docs/security-review.md](docs/security-review.md).

## Production warning

This repository is a reference implementation. A production deployment requires independent security review, dependency management, IAM review, authentication/authorization, monitoring, and compliance validation.
