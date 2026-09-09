# MobileShield Android Security Assessment

## 1. Assessment Overview

MobileShield is a synthetic Android application-security lab designed to demonstrate the identification, prioritization, remediation and automated validation of common mobile security weaknesses.

The assessment compares two implementations:

- `app/vulnerable`: intentionally insecure Android implementation.
- `app/remediated`: hardened implementation containing corrective security controls.

> **Training notice:** All application data, identities, endpoints, credentials and findings are synthetic. The project contains no production application, customer data or authentic secrets.

## 2. Assessment Objectives

The assessment was designed to:

- Review Android application and network-security configurations.
- Identify insecure coding and data-handling practices.
- Map findings to OWASP MASVS and MASWE.
- Prioritize findings according to technical severity.
- Implement a secure reference version.
- Validate remediation through automated regression checks.
- Produce repeatable security evidence suitable for CI/CD integration.

## 3. Assessment Scope

| Component | Assessment Activity |
|---|---|
| Android manifest | Permissions, exported components, backup and debug configuration |
| Network security configuration | Cleartext traffic and certificate trust settings |
| Kotlin application logic | Secrets, logging, storage, hashing and input handling |
| Android WebView | JavaScript, file access, content access and exposed interfaces |
| Remediated implementation | Verification of corrective security controls |
| Python automation | Finding validation, prioritization and remediation regression testing |

## 4. Assessment Methodology

The review used a combination of:

1. Manual static application-security analysis.
2. Android manifest and network configuration review.
3. Pattern-based evidence validation.
4. OWASP MASVS and MASWE mapping.
5. Severity-based remediation prioritization.
6. Vulnerable-to-remediated implementation comparison.
7. Automated Python regression testing.

The assessment validates the presence of each weakness in the vulnerable implementation before verifying its removal or mitigation in the remediated implementation.

## 5. Executive Finding Summary

| Severity | Findings | Target SLA |
|---|---:|---:|
| Critical | 2 | 2 days |
| High | 6 | 7 days |
| Medium | 3 | 30 days |
| Low | 0 | 90 days |
| Informational | 0 | Monitor |
| **Total** | **11** | — |

The highest-risk issues involved an externally accessible Android component and a WebView JavaScript interface capable of exposing session information.

## 6. Detailed Findings

| ID | Finding | Severity | MASVS Group | MASWE |
|---|---|---|---|---|
| MS-005 | Exported Activity Without Access Control | Critical | MASVS-AUTH | MASWE-0018 |
| MS-006 | Unsafe JavaScript Interface Exposes Session Token | Critical | MASVS-PLATFORM | MASWE-0033 |
| MS-001 | Hardcoded API Key | High | MASVS-STORAGE | MASWE-0004 |
| MS-002 | Sensitive Data Written to Application Logs | High | MASVS-STORAGE | MASWE-0005 |
| MS-003 | Sensitive Data Stored in Plaintext SharedPreferences | High | MASVS-STORAGE | MASWE-0001 |
| MS-004 | Cleartext Network Traffic Permitted | High | MASVS-NETWORK | MASWE-0026 |
| MS-007 | WebView Allows Unsafe Local File Access | High | MASVS-PLATFORM | MASWE-0034 |
| MS-009 | Sensitive Application Data Included in Backups | High | MASVS-STORAGE | MASWE-0006 |
| MS-008 | Weak MD5 Hashing Used for Security-Sensitive Value | Medium | MASVS-CRYPTO | MASWE-0008 |
| MS-010 | Debuggable Application Configuration Enabled | Medium | MASVS-RESILIENCE | MASWE-0063 |
| MS-011 | Excessive External Storage Permissions | Medium | MASVS-PRIVACY | MASWE-0066 |

## 7. Critical Findings

### MS-005 — Exported Activity Without Access Control

**Risk:** Critical  
**Target SLA:** 2 days  
**Affected file:** `app/vulnerable/src/main/AndroidManifest.xml`

The vulnerable activity is exported and registers the custom action `com.mobileshield.OPEN_ACCOUNT` without enforcing an application permission or caller authorization.

A malicious application could invoke the component directly and supply attacker-controlled intent data.

**Security impact:**

- Unauthorized component invocation.
- Manipulation of account identifiers or session-related input.
- Exposure of sensitive application functionality.
- Possible authorization-control bypass.

**Remediation:**

The custom exported intent filter was removed. The remediated implementation no longer accepts the externally supplied account and session values used by the vulnerable implementation.

**Validation result:** Passed.

### MS-006 — Unsafe JavaScript Interface Exposes Session Token

**Risk:** Critical  
**Target SLA:** 2 days  
**Affected file:** `app/vulnerable/src/main/java/com/mobileshield/MainActivity.kt`

The vulnerable WebView exposes an Android JavaScript interface containing a method that returns the current session token.

If untrusted content executes inside the WebView, it could call the exposed interface and retrieve the session value.

**Security impact:**

- Session-token disclosure.
- Account impersonation.
- Unauthorized access to protected application functions.
- Expansion of a WebView content issue into native application compromise.

**Remediation:**

The JavaScript interface was removed and JavaScript execution was disabled in the remediated WebView.

**Validation result:** Passed.

## 8. High Findings

### MS-001 — Hardcoded API Key

A demonstration API key was embedded directly in the Kotlin source code. Secrets stored in an application package can be recovered through static analysis or reverse engineering.

The remediated implementation contains no embedded API key. Production secrets should remain on trusted server-side systems and short-lived credentials should be issued only after authentication.

### MS-002 — Sensitive Application Logging

The vulnerable implementation writes the account identifier, session token and API key to debug logs.

Sensitive values were removed from application logging. Security-relevant telemetry should use non-sensitive identifiers and production-safe logging controls.

### MS-003 — Plaintext Sensitive Storage

The session token and API key were written to standard `SharedPreferences` without application-level encryption.

The remediated version does not persist these values. If sensitive local storage becomes necessary, it should use Android Keystore-backed encryption with appropriate lifecycle controls.

### MS-004 — Cleartext Network Traffic

The vulnerable application uses an HTTP API endpoint and explicitly permits cleartext traffic.

The remediated application uses HTTPS and disables cleartext traffic in both the manifest and network-security configuration.

### MS-007 — Unsafe WebView File Access

The vulnerable WebView enables JavaScript, local file access, content-provider access and universal access from file URLs.

The remediated configuration disables these capabilities and restricts navigation to the expected HTTPS scheme and application host.

### MS-009 — Sensitive Data Included in Backups

The vulnerable manifest enables application backup while the application stores sensitive session information locally.

The remediated manifest disables application backups for the demonstration application.

## 9. Medium Findings

### MS-008 — Weak MD5 Hashing

The vulnerable implementation uses MD5 to derive an account reference. MD5 is cryptographically broken and inappropriate for security-sensitive hashing.

The remediated implementation uses SHA-256. Password storage would require a dedicated password-hashing algorithm rather than a general-purpose hash.

### MS-010 — Debuggable Application

The vulnerable manifest explicitly enables the debuggable flag, increasing the risk of runtime inspection and application manipulation.

The remediated manifest disables debugging.

### MS-011 — Excessive Storage Permissions

The vulnerable application requests external-storage read and write permissions despite not requiring them for its demonstrated functionality.

The remediated manifest removes both permissions and retains only the required internet permission.

## 10. Remediation Validation

Automated validation confirms that:

- All 11 findings have corresponding security controls.
- Vulnerable evidence exists for every registered finding.
- Hardcoded API credentials are absent from the secure implementation.
- Sensitive debug logging has been removed.
- Sensitive values are not stored in plaintext preferences.
- HTTPS is used and cleartext communication is disabled.
- The unsafe custom intent entry point is removed.
- The JavaScript bridge is removed.
- WebView access is restricted.
- MD5 is replaced with SHA-256.
- Application backup and debugging are disabled.
- Unnecessary storage permissions are removed.

| Validation Outcome | Count |
|---|---:|
| Passed | 11 |
| Failed | 0 |
| Closed | 11 |
| Open | 0 |
| Coverage | 100% |

## 11. Residual Risk

The automated checks validate the security properties represented by the source files in this lab. They do not replace:

- Testing of a compiled and signed APK.
- Runtime testing on physical devices and emulators.
- Dependency and software-composition analysis.
- Backend API authorization testing.
- Certificate and transport validation against a deployed environment.
- Manual reverse engineering and dynamic instrumentation.
- Platform-specific testing across supported Android versions.

A production assessment should include static analysis, dynamic analysis, API testing, dependency scanning and device-level validation.

## 12. Recommended Security Controls

1. Keep secrets and privileged operations on trusted backend systems.
2. Use HTTPS exclusively and enforce secure network configuration.
3. Treat deep links, intents and inter-process input as untrusted.
4. Minimize exported Android components and enforce authorization.
5. Disable unnecessary WebView capabilities.
6. Avoid exposing sensitive native functionality to JavaScript.
7. Store sensitive data only when operationally necessary.
8. Protect stored secrets using Android Keystore-backed encryption.
9. Remove sensitive logging and debug features from release builds.
10. Request only permissions required by application functionality.
11. Add mobile-security regression validation to CI/CD pipelines.

## 13. Assessment Conclusion

The vulnerable MobileShield implementation contained 11 security findings spanning data storage, network communication, Android component exposure, WebView security, cryptography, application hardening and permission management.

The remediated implementation introduces defensive controls for every registered finding. Automated validation reports 11 passed controls, zero failed controls and complete remediation coverage.

This project demonstrates an evidence-based mobile application-security workflow that connects technical findings to standards mapping, code remediation and repeatable security validation.