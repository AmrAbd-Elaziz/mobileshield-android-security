# OWASP MASVS and MASWE Mapping

## 1. Purpose

This document maps the MobileShield Android security findings to the OWASP Mobile Application Security Verification Standard (MASVS) and Mobile Application Security Weakness Enumeration (MASWE).

The mapping connects each identified weakness to:

- The relevant MASVS security area.
- A specific MASWE weakness.
- Source-code or configuration evidence.
- The implemented remediation control.
- Automated validation evidence.

> This mapping supports assessment traceability. It does not claim formal OWASP certification or complete verification of every MASVS control.

## 2. Framework Overview

OWASP MASVS defines security requirements for mobile applications across the following control groups:

| MASVS Group | Security Area |
|---|---|
| MASVS-STORAGE | Secure storage of sensitive data |
| MASVS-CRYPTO | Cryptographic functionality |
| MASVS-AUTH | Authentication and authorization |
| MASVS-NETWORK | Secure network communication |
| MASVS-PLATFORM | Secure interaction with the mobile platform |
| MASVS-CODE | Secure code and dependency practices |
| MASVS-RESILIENCE | Resistance to reverse engineering and tampering |
| MASVS-PRIVACY | Protection of user privacy |

MASWE provides specific mobile application weakness definitions associated with these security areas.

## 3. Finding-to-Standard Mapping

| ID | Finding | Severity | MASVS Group | MASWE ID | MASWE Weakness |
|---|---|---|---|---|---|
| MS-001 | Hardcoded API Key | High | MASVS-STORAGE | MASWE-0004 | Sensitive Data Hardcoded in the App Package |
| MS-002 | Sensitive Data Written to Application Logs | High | MASVS-STORAGE | MASWE-0005 | Insertion of Sensitive Data into Logs |
| MS-003 | Sensitive Data Stored in Plaintext SharedPreferences | High | MASVS-STORAGE | MASWE-0001 | Sensitive Data Stored Unencrypted in Private Storage |
| MS-004 | Cleartext Network Traffic Permitted | High | MASVS-NETWORK | MASWE-0026 | Network Traffic Not Encrypted |
| MS-005 | Exported Activity Without Access Control | Critical | MASVS-AUTH | MASWE-0018 | Lack of Authentication or Authorization on App Components |
| MS-006 | Unsafe JavaScript Interface Exposes Session Token | Critical | MASVS-PLATFORM | MASWE-0033 | Sensitive Native Functionality Exposed in WebViews |
| MS-007 | WebView Allows Unsafe Local File Access | High | MASVS-PLATFORM | MASWE-0034 | WebViews Allow Access to Local Resources with Untrusted Content |
| MS-008 | Weak MD5 Hashing Used for Security-Sensitive Value | Medium | MASVS-CRYPTO | MASWE-0008 | Improper Hashing |
| MS-009 | Sensitive Application Data Included in Backups | High | MASVS-STORAGE | MASWE-0006 | Sensitive Data Not Excluded From Backup |
| MS-010 | Debuggable Application Configuration Enabled | Medium | MASVS-RESILIENCE | MASWE-0063 | Debug Mechanisms Not Disabled |
| MS-011 | Excessive External Storage Permissions | Medium | MASVS-PRIVACY | MASWE-0066 | Inadequate Permission Management |

## 4. MASVS Coverage Summary

| MASVS Group | Findings | Finding IDs |
|---|---:|---|
| MASVS-STORAGE | 4 | MS-001, MS-002, MS-003, MS-009 |
| MASVS-CRYPTO | 1 | MS-008 |
| MASVS-AUTH | 1 | MS-005 |
| MASVS-NETWORK | 1 | MS-004 |
| MASVS-PLATFORM | 2 | MS-006, MS-007 |
| MASVS-CODE | 0 | Not directly represented |
| MASVS-RESILIENCE | 1 | MS-010 |
| MASVS-PRIVACY | 1 | MS-011 |
| **Total** | **11** | — |

The project provides direct coverage of seven of the eight MASVS security areas.

MASVS-CODE is not represented as a standalone finding because the current synthetic dataset does not include a vulnerable dependency, unsupported platform version or unsafe dynamic code-loading scenario.

## 5. MASVS-STORAGE Mapping

### MS-001 — MASWE-0004

The vulnerable Kotlin source contains a hardcoded demonstration API key.

The remediated implementation removes the embedded credential. Privileged API secrets should remain on trusted backend systems.

### MS-002 — MASWE-0005

The vulnerable implementation writes session and API-key information to application logs.

The remediated version removes sensitive logging.

Relevant OWASP testing guidance includes removing logging code and disabling verbose production logging.

### MS-003 — MASWE-0001

The vulnerable implementation stores a session token and API key in plaintext `SharedPreferences`.

The remediated version does not persist either value.

Where local sensitive storage is required, Android Keystore-backed encryption and appropriate credential lifecycle controls should be used.

### MS-009 — MASWE-0006

The vulnerable application enables backups while storing sensitive information locally.

The remediated manifest disables application backup.

Production applications should also define appropriate backup and data-extraction rules for their supported Android versions.

## 6. MASVS-CRYPTO Mapping

### MS-008 — MASWE-0008

The vulnerable activity uses MD5 to generate a security-sensitive account reference.

The remediated implementation uses SHA-256 for the non-secret demonstration reference.

This change does not imply that SHA-256 is appropriate for password storage. Passwords require a dedicated password-hashing algorithm, unique salt and suitable work factor.

## 7. MASVS-AUTH Mapping

### MS-005 — MASWE-0018

The vulnerable manifest exposes a custom activity action without caller authentication or authorization.

The remediated implementation removes the custom exported entry point and no longer consumes the externally supplied account or session values.

Applications that require exported components should:

- Enforce appropriate permissions.
- Authenticate and authorize callers.
- Validate all intent data.
- Prefer explicit internal intents.
- Minimize exposed functionality.

## 8. MASVS-NETWORK Mapping

### MS-004 — MASWE-0026

The vulnerable application uses an HTTP API endpoint and explicitly permits cleartext network communication.

The remediated version:

- Uses an HTTPS endpoint.
- Disables cleartext traffic in the manifest.
- Disables cleartext traffic in the network-security configuration.
- Trusts system certificate authorities only.

Testing a production build should additionally verify TLS configuration and server certificate validation at runtime.

## 9. MASVS-PLATFORM Mapping

### MS-006 — MASWE-0033

The vulnerable WebView exposes a native JavaScript interface capable of returning session data.

The remediated implementation removes the bridge and disables JavaScript because the demonstrated workflow does not require it.

### MS-007 — MASWE-0034

The vulnerable WebView permits JavaScript, local file access, content-provider access and universal access from file URLs.

The remediated version disables these capabilities and restricts navigation to the approved HTTPS host.

## 10. MASVS-RESILIENCE Mapping

### MS-010 — MASWE-0063

The vulnerable manifest explicitly enables application debugging.

The remediated manifest disables debugging.

A production release pipeline should also verify:

- Release signing configuration.
- Removal of test functionality.
- Removal of debug symbols where appropriate.
- Absence of development endpoints and diagnostic controls.

## 11. MASVS-PRIVACY Mapping

### MS-011 — MASWE-0066

The vulnerable application requests external-storage read and write permissions without a demonstrated business requirement.

The remediated manifest removes both permissions and retains only the internet permission.

This supports least privilege and reduces unnecessary access to user or device data.

## 12. Relevant OWASP MASTG Practices

| Practice | Application to MobileShield |
|---|---|
| Remove logging code | Supports remediation of MS-002 |
| Exclude sensitive data from backups | Supports remediation of MS-009 |
| Disable the debuggable manifest flag | Supports remediation of MS-010 |
| Use secure cryptographic algorithms | Supports remediation of MS-008 |
| Disable JavaScript when unnecessary | Supports remediation of MS-006 and MS-007 |
| Disable WebView file and content access | Supports remediation of MS-007 |
| Validate WebView input and destinations | Supports remediation of MS-007 |
| Restrict access to Android components | Supports remediation of MS-005 |
| Sanitize data from external components | Supports remediation of MS-005 |
| Restrict native functionality exposed through WebViews | Supports remediation of MS-006 |
| Minimize application permissions | Supports remediation of MS-011 |

## 13. Automated Validation Traceability

| Evidence | Purpose |
|---|---|
| `data/raw/mobile-security-findings.json` | Source finding register and standards mapping |
| `data/processed/analyzed-findings.json` | Validated and prioritized finding data |
| `data/processed/remediation-validation.json` | Per-finding remediation results |
| `scripts/analyze_findings.py` | Schema validation and severity prioritization |
| `scripts/validate_remediation.py` | Vulnerable-to-remediated control comparison |
| `tests/test_analyze_findings.py` | Finding-analysis regression tests |
| `tests/test_validate_remediation.py` | Remediation regression tests |
| `app/vulnerable/` | Deliberately insecure implementation |
| `app/remediated/` | Hardened reference implementation |

## 14. Mapping Limitations

This project demonstrates targeted standards mapping for a controlled synthetic scenario.

It does not constitute full MASVS verification because it does not currently include:

- Testing of a compiled release APK.
- Dynamic analysis on an Android device.
- Dependency and software-composition analysis.
- Backend API authentication and authorization testing.
- Full coverage of all MASVS controls.
- Formal review by an independent assessor.

## 15. References

- OWASP Mobile Application Security Verification Standard: <https://mas.owasp.org/MASVS/>
- OWASP Mobile Application Security Weakness Enumeration: <https://mas.owasp.org/MASWE/>
- OWASP Mobile Application Security Testing Guide: <https://mas.owasp.org/MASTG/>

## 16. Conclusion

MobileShield maps 11 Android security findings across seven MASVS security areas and associates each finding with a specific MASWE weakness.

The mapping is supported by source evidence, a hardened implementation and automated remediation validation. This creates traceability from weakness identification through remediation and evidence-based closure.