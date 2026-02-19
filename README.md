# TaskForge — Vulnerability Test Application

A deliberately vulnerable Python Flask micro-service used for **end-to-end
testing** of the Ceragon / CodeFence scanning pipeline.

> **⚠️ Do NOT deploy this application in any real environment.**

## Intentional Vulnerabilities

### CRITICAL
| # | Type | File | Line(s) |
|---|------|------|---------|
| 1 | SQL Injection (login) | `src/app.py` | ~78-82 |
| 2 | SQL Injection (search) | `src/app.py` | ~100-103 |
| 3 | OS Command Injection | `src/app.py` | ~120-122 |
| 4 | Hardcoded AWS credentials | `secrets/.env` | 6-7 |

### HIGH
| # | Type | File | Line(s) |
|---|------|------|---------|
| 5 | Weak MD5 password hashing | `src/app.py` | ~60 |
| 6 | Flask debug mode enabled | `src/app.py` | ~216 |
| 7 | SSRF via user-controlled URL | `src/app.py` | ~140-142 |
| 8 | Hardcoded JWT signing secret | `src/app.py` | ~30 |

### MEDIUM
| # | Type | File | Line(s) |
|---|------|------|---------|
| 9 | Unsafe `yaml.load()` | `src/app.py` | ~160 |
| 10 | Unsafe `pickle.loads()` | `src/app.py` | ~170-172 |

### LOW
| # | Type | File | Line(s) |
|---|------|------|---------|
| 11 | Sensitive data in debug log | `src/app.py` | ~82 |
| 12 | Permissive CORS (`*`) | `src/app.py` | ~45 |

### Dependency CVEs (pip-audit / osv-scanner)
| Package | Version | Known CVEs |
|---------|---------|-----------|
| flask | 2.2.0 | CVE-2023-30861 |
| pyyaml | 5.4.1 | CVE-2020-14343 |
| requests | 2.28.0 | CVE-2023-32681 |
| jinja2 | 3.1.2 | CVE-2024-22195 |
| PyJWT | 2.4.0 | CVE-2022-29217 |

### CI / Workflow Issues (zizmor)
| # | Type | File |
|---|------|------|
| 13 | `curl \| bash` pattern | `.github/workflows/ci.yml` |
| 14 | Overly broad permissions | `.github/workflows/ci.yml` |

## Running Locally

```bash
pip install -r requirements.txt
python -m src.app
```

## Expected Scanner Results

The Ceragon scanner pipeline should produce:
- **Check Run** with severity annotations on each finding
- **PR Comment** with summary table & remediation guidance
- **Inline Review Comments** on changed lines (Phase 2 feature)
- **SARIF Upload** to GitHub Code Scanning
