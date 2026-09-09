# MobileShield — Android Application Security Lab

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![Android](https://img.shields.io/badge/Platform-Android-3DDC84?logo=android&logoColor=white)
![Kotlin](https://img.shields.io/badge/Language-Kotlin-7F52FF?logo=kotlin&logoColor=white)
![OWASP MASVS](https://img.shields.io/badge/OWASP-MASVS-ED1C24)
![Tests](https://img.shields.io/badge/Tests-18%20Passing-2EA44F)
[![MobileShield Validation](https://github.com/AmrAbd-Elaziz/mobileshield-android-security/actions/workflows/mobileshield-validation.yml/badge.svg)](https://github.com/AmrAbd-Elaziz/mobileshield-android-security/actions/workflows/mobileshield-validation.yml)

An Android application-security portfolio lab demonstrating vulnerable-code review, OWASP MASVS and MASWE mapping, secure remediation and automated evidence-based validation.

> **Security notice:** This project contains intentionally vulnerable training code and synthetic secrets, endpoints and findings. It contains no production application, customer data or authentic credentials.

## Project Objective

MobileShield demonstrates an end-to-end mobile application-security workflow:

1. Model Android application threats.
2. Review insecure source code and configuration.
3. Register and prioritize security findings.
4. Map findings to OWASP MASVS and MASWE.
5. Implement a hardened reference version.
6. Validate each remediation control automatically.
7. Generate executive and technical security reports.
8. Prevent security regressions through automated tests and CI/CD.

## Why This Project Matters

Mobile findings often remain disconnected from development remediation and closure evidence.

MobileShield connects:

```text
Threat Model
    ↓
Vulnerable Android Evidence
    ↓
Security Findings
    ↓
OWASP MASVS / MASWE Mapping
    ↓
Hardened Implementation
    ↓
Automated Remediation Validation
    ↓
Executive and Technical Reporting
```

The objective is not simply to identify insecure patterns, but to prove that corrective controls were implemented.

## Security Findings

| Severity | Findings | Target SLA |
|---|---:|---:|
| Critical | 2 | 2 days |
| High | 6 | 7 days |
| Medium | 3 | 30 days |
| Low | 0 | 90 days |
| **Total** | **11** | — |

The highest-risk findings involve:

- An unprotected exported Android activity.
- A JavaScript bridge capable of exposing session information.
- Hardcoded application credentials.
- Sensitive logging and plaintext storage.
- Cleartext network traffic.
- Unsafe WebView configuration.

## Remediation Outcome

| Validation Metric | Result |
|---|---:|
| Registered findings | 11 |
| Remediation controls | 11 |
| Controls passed | 11 |
| Controls failed | 0 |
| Findings closed | 11 |
| Evidence coverage | 100% |
| Automated tests | 18 passing |

## Vulnerable vs. Remediated

| Security Area | Vulnerable Implementation | Remediated Implementation |
|---|---|---|
| API credentials | Hardcoded in Kotlin source | Removed from mobile client |
| Logging | Session and API key logged | Sensitive logging removed |
| Local storage | Plaintext preferences | Sensitive persistence removed |
| Network traffic | HTTP and cleartext allowed | HTTPS and cleartext blocked |
| Android components | Custom action exported | Unnecessary entry point removed |
| WebView bridge | Session exposed to JavaScript | Native bridge removed |
| WebView access | JavaScript and file access enabled | Unnecessary capabilities disabled |
| Hashing | MD5 | SHA-256 |
| Application backup | Enabled | Disabled |
| Debug configuration | Enabled | Disabled |
| Permissions | External storage requested | Unnecessary permissions removed |

## OWASP Coverage

| MASVS Group | Findings |
|---|---:|
| MASVS-STORAGE | 4 |
| MASVS-CRYPTO | 1 |
| MASVS-AUTH | 1 |
| MASVS-NETWORK | 1 |
| MASVS-PLATFORM | 2 |
| MASVS-CODE | 0 |
| MASVS-RESILIENCE | 1 |
| MASVS-PRIVACY | 1 |

The project maps 11 findings across seven OWASP MASVS security areas.

Each finding is also associated with a specific OWASP MASWE weakness identifier.

## Featured Findings

| ID | Finding | Severity | Mapping |
|---|---|---|---|
| MS-005 | Exported Activity Without Access Control | Critical | MASWE-0018 |
| MS-006 | Unsafe JavaScript Interface Exposes Session Token | Critical | MASWE-0033 |
| MS-001 | Hardcoded API Key | High | MASWE-0004 |
| MS-002 | Sensitive Data Written to Application Logs | High | MASWE-0005 |
| MS-003 | Sensitive Data Stored in Plaintext SharedPreferences | High | MASWE-0001 |
| MS-004 | Cleartext Network Traffic Permitted | High | MASWE-0026 |
| MS-007 | WebView Allows Unsafe Local File Access | High | MASWE-0034 |
| MS-009 | Sensitive Application Data Included in Backups | High | MASWE-0006 |

## Repository Structure

```text
mobileshield-android-security/
├── .github/
│   └── workflows/
│       └── mobileshield-validation.yml
├── app/
│   ├── vulnerable/
│   │   └── src/main/
│   │       ├── AndroidManifest.xml
│   │       ├── java/com/mobileshield/
│   │       │   └── MainActivity.kt
│   │       └── res/xml/
│   │           └── network_security_config.xml
│   └── remediated/
│       └── src/main/
│           ├── AndroidManifest.xml
│           ├── java/com/mobileshield/
│           │   └── MainActivity.kt
│           └── res/xml/
│               └── network_security_config.xml
├── data/
│   ├── raw/
│   │   └── mobile-security-findings.json
│   └── processed/
│       ├── analyzed-findings.json
│       └── remediation-validation.json
├── docs/
│   ├── THREAT-MODEL.md
│   ├── SECURITY-ASSESSMENT.md
│   ├── REMEDIATION-GUIDE.md
│   └── OWASP-MASVS-MAPPING.md
├── reports/
│   ├── executive/
│   │   └── EXECUTIVE-MOBILE-SECURITY-REPORT.md
│   └── technical/
│       └── MOBILE-SECURITY-ASSESSMENT-REPORT.md
├── scripts/
│   ├── analyze_findings.py
│   ├── validate_remediation.py
│   ├── generate_executive_report.py
│   └── generate_technical_report.py
├── tests/
│   ├── test_analyze_findings.py
│   └── test_validate_remediation.py
├── .gitignore
├── README.md
└── requirements.txt
```

## Automated Finding Analysis

Run the finding analyzer:

```bash
python3 scripts/analyze_findings.py
```

The analyzer:

- Validates the finding schema.
- Rejects missing or empty fields.
- Rejects unsupported severities.
- Detects duplicate finding IDs.
- Assigns severity scores.
- Assigns remediation SLAs.
- Sorts findings by severity.
- Generates processed JSON evidence.

Expected summary:

```text
Findings analyzed: 11
Critical: 2
High: 6
Medium: 3
Low: 0
Informational: 0
```

## Automated Remediation Validation

Run the vulnerable-to-remediated comparison:

```bash
python3 scripts/validate_remediation.py
```

The validator confirms:

- Every registered finding has a matching check.
- Vulnerable evidence exists for every finding.
- Corrective controls exist in the hardened version.
- Known unsafe patterns are absent.
- Reintroduced weaknesses cause failure.

Expected result:

```text
Remediation validation passed
Controls validated: 11
Passed: 11
Failed: 0
```

## Automated Tests

Run the complete test suite:

```bash
PYTHONDONTWRITEBYTECODE=1 \
python3 -m unittest discover -s tests -v
```

The 18 tests cover:

- Required finding fields.
- Empty-value rejection.
- Severity validation.
- Finding ID validation.
- MASWE ID validation.
- Duplicate ID detection.
- Severity scoring and SLA assignment.
- Finding prioritization.
- Remediation control coverage.
- Source-to-check traceability.
- Generated closure evidence.
- Missing security evidence.
- Reintroduced HTTP exposure.
- Reintroduced backup exposure.

## Generate Security Reports

Generate the source analysis:

```bash
python3 scripts/analyze_findings.py
```

Validate remediation:

```bash
python3 scripts/validate_remediation.py
```

Generate the executive report:

```bash
python3 scripts/generate_executive_report.py \
  --assessment-date 2026-09-09
```

Generate the technical report:

```bash
python3 scripts/generate_technical_report.py
```

## Project Documentation

- [Threat Model](docs/THREAT-MODEL.md)
- [Security Assessment](docs/SECURITY-ASSESSMENT.md)
- [Remediation Guide](docs/REMEDIATION-GUIDE.md)
- [OWASP MASVS and MASWE Mapping](docs/OWASP-MASVS-MAPPING.md)
- [Executive Mobile Security Report](reports/executive/EXECUTIVE-MOBILE-SECURITY-REPORT.md)
- [Technical Security Assessment](reports/technical/MOBILE-SECURITY-ASSESSMENT-REPORT.md)

## Security Engineering Decisions

- Mobile clients are treated as untrusted environments.
- Privileged credentials remain outside the application package.
- External intents are considered attacker-controlled input.
- Sensitive authentication state is not accepted through intents.
- WebView functionality follows least privilege.
- Cleartext communication is prohibited.
- Sensitive values are excluded from logs and unnecessary storage.
- Findings are closed only after automated remediation validation.
- Security regressions are designed to fail the CI pipeline.

## Assessment Limitations

MobileShield is a source-based training project and does not currently include:

- A complete Gradle Android build.
- A compiled and signed release APK.
- Physical-device or emulator testing.
- Backend API security testing.
- Third-party dependency analysis.
- Runtime instrumentation.
- Full MASVS verification.
- Formal OWASP certification.

## Planned Enhancements

- Add MobSF static-analysis evidence.
- Add Android lint and secret scanning.
- Add Semgrep mobile-security rules.
- Add compiled APK inspection.
- Add dynamic testing evidence.
- Add an interactive findings dashboard.
- Publish the dashboard with GitHub Pages.
- Add screenshots and a portfolio cover image.

## References

- [OWASP MASVS](https://mas.owasp.org/MASVS/)
- [OWASP MASWE](https://mas.owasp.org/MASWE/)
- [OWASP MASTG](https://mas.owasp.org/MASTG/)
- [Android Security Documentation](https://developer.android.com/privacy-and-security/security-best-practices)

## Author

**Amr Abdelaziz**

Cybersecurity Engineer specializing in security engineering, application security, vulnerability management, cloud security and DevSecOps.

> Validating risk. Engineering trust.