# Strict Mode SAST Coverage

## Overview

In strict/offline mode, Semgrep uses a vendored rule pack (`configs/semgrep-rules.yml`)
instead of downloading rules from the Semgrep registry. This provides deterministic,
offline-safe scanning but with **reduced rule coverage** compared to standard mode.

## Current Coverage

| # | Vulnerability Class | Rule Count | CWEs Covered |
|---|-------------------|------------|--------------|
| 1 | SQL Injection | 2 | CWE-89 |
| 2 | Cross-Site Scripting (XSS) | 2 | CWE-79 |
| 3 | Command Injection | 2 | CWE-78 |
| 4 | Path Traversal | 1 | CWE-22 |
| 5 | SSRF | 1 | CWE-918 |
| 6 | Hardcoded Secrets | 1 | CWE-798 |
| 7 | Weak Cryptography | 1 | CWE-327 |
| 8 | Insecure Deserialization | 1 | CWE-502 |
| 9 | Open Redirect | 1 | CWE-601 |
|   | **Total** | **13 rules** | **9 classes** |

## Comparison to Standard Mode

Standard mode pulls `p/security-audit` + `p/owasp-top-ten` + language packs from the
Semgrep registry, which includes **300+ rules** covering **25+ vulnerability classes**.

### Not covered in strict mode (Semgrep)

- Authentication/authorization flaws beyond hardcoded secrets
- Race conditions
- Information disclosure patterns
- Insecure configuration patterns
- Language-specific anti-patterns (e.g., prototype pollution, eval usage)
- Many framework-specific rules (Express, Django, Flask, React, etc.)

### Compensating controls

- **Bandit** (bundled in strict mode) provides additional Python SAST coverage
- **CodeQL** (if available) provides deep dataflow analysis
- **Checkov** covers IaC misconfigurations
- **Gitleaks** covers secret detection comprehensively

## Recommendation

For maximum SAST coverage in strict mode, consider:
1. Periodically updating the vendored rule pack from the registry
2. Enabling CodeQL if GHAS is available
3. Adding custom rules to `configs/semgrep-rules.yml` for your tech stack
