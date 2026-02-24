# githubapptest

Intentionally vulnerable, realistic sample repository for validating the
GitHub vulnerability scanning application.

This codebase is intentionally seeded with **exactly 30 vulnerabilities**,
each tagged in source code with a unique internal marker so scanner
precision can be measured as:

- True positives: 30
- False negatives: 0
- False positives: 0 (target)

## Project layout

- `src/` - Express API and service modules
- `scripts/` - Operational scripts with realistic anti-patterns
- `python/` - Auxiliary analysis helpers
- `Dockerfile` / `docker-compose.yml` - runnable local environment

## Run locally

```bash
npm install
npm run setup-db
npm run start
```

## Vulnerability index (expected findings)

1. Hardcoded JWT secret
2. Hardcoded third-party API key
3. Weak password hashing (MD5)
4. SQL injection in email lookup
5. SQL injection in role filter
6. Sensitive data in logs (plaintext password)
7. JWT decoded without signature verification
8. Missing authorization on admin endpoint
9. IDOR user record exposure
10. Command injection in backup endpoint
11. Path traversal in file download
12. Unrestricted file upload
13. Open redirect in logout flow
14. Reflected XSS in template rendering
15. Stored XSS in profile bio storage
16. Prototype pollution via deep merge
17. SSRF via user-supplied URL
18. TLS certificate validation disabled
19. Eval of untrusted input
20. Insecure session token generation
21. Predictable temp file for sensitive report
22. Unsafe YAML deserialization
23. XXE-capable XML parser configuration
24. Command injection in import script
25. Dynamic code execution from serialized input
26. Server-side template code execution through untrusted snippet rendering
27. Unsafe Python pickle deserialization
28. Shell command execution with user-controlled host in Python helper
29. Insecure temporary file path generation using `mktemp`
30. Dynamic Python `eval` of untrusted expression input

## Safety note

This repository is for controlled security testing only. Do not deploy or
reuse this code in production systems.
