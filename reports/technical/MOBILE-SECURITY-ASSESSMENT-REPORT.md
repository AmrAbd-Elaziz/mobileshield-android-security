# MobileShield Technical Security Assessment

## 1. Report Scope

This report documents a source-based security assessment of the synthetic MobileShield Android application.

The assessment compares an intentionally vulnerable implementation with a hardened reference implementation and validates remediation through automated checks.

> All application data, endpoints, credentials and findings are synthetic and intended exclusively for authorized security training.

## 2. Evidence Summary

| Evidence Metric | Result |
|---|---:|
| Findings analyzed | 11 |
| Critical findings | 2 |
| High findings | 6 |
| Medium findings | 3 |
| Remediation controls passed | 11 |
| Remediation controls failed | 0 |

## 3. Assessment Components

| Component | Location |
|---|---|
| Vulnerable Android implementation | `app/vulnerable/` |
| Hardened Android implementation | `app/remediated/` |
| Source finding register | `data/raw/mobile-security-findings.json` |
| Prioritized findings | `data/processed/analyzed-findings.json` |
| Remediation evidence | `data/processed/remediation-validation.json` |

## 4. Finding Register

| ID | Finding | Severity | Category | MASVS | MASWE | SLA | Status |
|---|---|---|---|---|---|---:|---|
| MS-005 | Exported Activity Without Access Control | Critical | Component Security | MASVS-AUTH | MASWE-0018 | 2 days | Closed |
| MS-006 | Unsafe JavaScript Interface Exposes Session Token | Critical | WebView Security | MASVS-PLATFORM | MASWE-0033 | 2 days | Closed |
| MS-001 | Hardcoded API Key | High | Data Storage | MASVS-STORAGE | MASWE-0004 | 7 days | Closed |
| MS-002 | Sensitive Data Written to Application Logs | High | Data Leakage | MASVS-STORAGE | MASWE-0005 | 7 days | Closed |
| MS-003 | Sensitive Data Stored in Plaintext SharedPreferences | High | Data Storage | MASVS-STORAGE | MASWE-0001 | 7 days | Closed |
| MS-004 | Cleartext Network Traffic Permitted | High | Network Communication | MASVS-NETWORK | MASWE-0026 | 7 days | Closed |
| MS-007 | WebView Allows Unsafe Local File Access | High | WebView Security | MASVS-PLATFORM | MASWE-0034 | 7 days | Closed |
| MS-009 | Sensitive Application Data Included in Backups | High | Data Storage | MASVS-STORAGE | MASWE-0006 | 7 days | Closed |
| MS-008 | Weak MD5 Hashing Used for Security-Sensitive Value | Medium | Cryptography | MASVS-CRYPTO | MASWE-0008 | 30 days | Closed |
| MS-010 | Debuggable Application Configuration Enabled | Medium | Application Hardening | MASVS-RESILIENCE | MASWE-0063 | 30 days | Closed |
| MS-011 | Excessive External Storage Permissions | Medium | Permission Management | MASVS-PRIVACY | MASWE-0066 | 30 days | Closed |

## 5. Detailed Technical Findings

### 5.1 MS-005 — Exported Activity Without Access Control

**Severity:** Critical

**Category:** Component Security

**Standards mapping:** MASVS-AUTH / MASWE-0018

**Affected file:** `app/vulnerable/src/main/AndroidManifest.xml`

**Source:** Manifest Analysis

**Evidence:**

> `MainActivity is exported with an unprotected custom intent action`

**Security impact:**

An external application may invoke sensitive functionality without sufficient authorization.

**Recommended remediation:**

Remove the unnecessary custom exported action and do not trust externally supplied auth state.

**Implemented control:**

Unprotected custom intent entry point removed

**Validation status:** Passed

**Final disposition:** Closed

### 5.2 MS-006 — Unsafe JavaScript Interface Exposes Session Token

**Severity:** Critical

**Category:** WebView Security

**Standards mapping:** MASVS-PLATFORM / MASWE-0033

**Affected file:** `app/vulnerable/src/main/java/com/mobileshield/MainActivity.kt`

**Source:** Manual Static Analysis

**Evidence:**

> `addJavascriptInterface exposes getSessionToken`

**Security impact:**

Untrusted WebView content may access native functionality and retrieve session information.

**Recommended remediation:**

Remove the JavaScript bridge and do not expose session information to web content.

**Implemented control:**

JavaScript interface exposing session data removed

**Validation status:** Passed

**Final disposition:** Closed

### 5.3 MS-001 — Hardcoded API Key

**Severity:** High

**Category:** Data Storage

**Standards mapping:** MASVS-STORAGE / MASWE-0004

**Affected file:** `app/vulnerable/src/main/java/com/mobileshield/MainActivity.kt`

**Source:** Manual Static Analysis

**Evidence:**

> `private const val API_KEY`

**Security impact:**

Embedded credentials can be extracted through application decompilation or static analysis.

**Recommended remediation:**

Remove embedded API credentials and keep privileged secrets on trusted backend systems.

**Implemented control:**

Hardcoded API key removed

**Validation status:** Passed

**Final disposition:** Closed

### 5.4 MS-002 — Sensitive Data Written to Application Logs

**Severity:** High

**Category:** Data Leakage

**Standards mapping:** MASVS-STORAGE / MASWE-0005

**Affected file:** `app/vulnerable/src/main/java/com/mobileshield/MainActivity.kt`

**Source:** Manual Static Analysis

**Evidence:**

> `Log.d includes sessionToken and API_KEY`

**Security impact:**

Sensitive log entries may disclose session or credential information to unauthorized parties.

**Recommended remediation:**

Remove sensitive debug logs and retain only production-safe operational telemetry.

**Implemented control:**

Sensitive debug logging removed

**Validation status:** Passed

**Final disposition:** Closed

### 5.5 MS-003 — Sensitive Data Stored in Plaintext SharedPreferences

**Severity:** High

**Category:** Data Storage

**Standards mapping:** MASVS-STORAGE / MASWE-0001

**Affected file:** `app/vulnerable/src/main/java/com/mobileshield/MainActivity.kt`

**Source:** Manual Static Analysis

**Evidence:**

> `SharedPreferences stores session_token and api_key`

**Security impact:**

Plaintext local storage may expose sensitive values through device access, backup or malware.

**Recommended remediation:**

Avoid persisting session and API credentials; use Keystore-backed protection when required.

**Implemented control:**

Sensitive plaintext preference storage removed

**Validation status:** Passed

**Final disposition:** Closed

### 5.6 MS-004 — Cleartext Network Traffic Permitted

**Severity:** High

**Category:** Network Communication

**Standards mapping:** MASVS-NETWORK / MASWE-0026

**Affected file:** `app/vulnerable/src/main/AndroidManifest.xml`

**Source:** Configuration Review

**Evidence:**

> `usesCleartextTraffic=true and cleartextTrafficPermitted=true`

**Security impact:**

Cleartext traffic can be intercepted or modified by a network-positioned attacker.

**Recommended remediation:**

Use HTTPS exclusively and disable cleartext traffic in Android network configuration.

**Implemented control:**

HTTPS enforced and cleartext traffic disabled

**Validation status:** Passed

**Final disposition:** Closed

### 5.7 MS-007 — WebView Allows Unsafe Local File Access

**Severity:** High

**Category:** WebView Security

**Standards mapping:** MASVS-PLATFORM / MASWE-0034

**Affected file:** `app/vulnerable/src/main/java/com/mobileshield/MainActivity.kt`

**Source:** Manual Static Analysis

**Evidence:**

> `allowFileAccess and allowUniversalAccessFromFileURLs are enabled`

**Security impact:**

Unsafe WebView settings increase exposure to local-resource access and malicious content.

**Recommended remediation:**

Disable unnecessary WebView capabilities and restrict navigation to the approved HTTPS host.

**Implemented control:**

WebView local and content access disabled

**Validation status:** Passed

**Final disposition:** Closed

### 5.8 MS-009 — Sensitive Application Data Included in Backups

**Severity:** High

**Category:** Data Storage

**Standards mapping:** MASVS-STORAGE / MASWE-0006

**Affected file:** `app/vulnerable/src/main/AndroidManifest.xml`

**Source:** Manifest Analysis

**Evidence:**

> `android:allowBackup=true`

**Security impact:**

Application backups may contain sensitive local data that can be recovered outside the app.

**Recommended remediation:**

Disable backups or explicitly exclude sensitive application data.

**Implemented control:**

Application backups disabled

**Validation status:** Passed

**Final disposition:** Closed

### 5.9 MS-008 — Weak MD5 Hashing Used for Security-Sensitive Value

**Severity:** Medium

**Category:** Cryptography

**Standards mapping:** MASVS-CRYPTO / MASWE-0008

**Affected file:** `app/vulnerable/src/main/java/com/mobileshield/MainActivity.kt`

**Source:** Manual Static Analysis

**Evidence:**

> `MessageDigest.getInstance("MD5")`

**Security impact:**

MD5 does not provide suitable collision resistance for security-sensitive hashing.

**Recommended remediation:**

Replace MD5 with an approved algorithm suitable for the intended security purpose.

**Implemented control:**

MD5 replaced with SHA-256

**Validation status:** Passed

**Final disposition:** Closed

### 5.10 MS-010 — Debuggable Application Configuration Enabled

**Severity:** Medium

**Category:** Application Hardening

**Standards mapping:** MASVS-RESILIENCE / MASWE-0063

**Affected file:** `app/vulnerable/src/main/AndroidManifest.xml`

**Source:** Manifest Analysis

**Evidence:**

> `android:debuggable=true`

**Security impact:**

Debug-enabled builds permit additional runtime inspection and application manipulation.

**Recommended remediation:**

Disable debugging and validate release-build configuration through CI/CD.

**Implemented control:**

Debuggable mode disabled

**Validation status:** Passed

**Final disposition:** Closed

### 5.11 MS-011 — Excessive External Storage Permissions

**Severity:** Medium

**Category:** Permission Management

**Standards mapping:** MASVS-PRIVACY / MASWE-0066

**Affected file:** `app/vulnerable/src/main/AndroidManifest.xml`

**Source:** Manifest Analysis

**Evidence:**

> `READ_EXTERNAL_STORAGE and WRITE_EXTERNAL_STORAGE permissions requested`

**Security impact:**

Unnecessary permissions increase access to device data and expand application attack surface.

**Recommended remediation:**

Remove external-storage permissions that are not required by application functionality.

**Implemented control:**

Unnecessary external-storage permissions removed

**Validation status:** Passed

**Final disposition:** Closed

## 6. Vulnerable Attack Surface

The vulnerable implementation contains multiple connected weaknesses:

- An external application can invoke the custom exported activity action.
- Intent-supplied account and session values are accepted without validation.
- Sensitive values are logged and stored in plaintext preferences.
- Cleartext HTTP content is loaded into an unsafe WebView.
- JavaScript can call a native bridge that exposes session information.
- Local file and content access are enabled inside the WebView.
- Debugging, backup and unnecessary permissions expand device-level exposure.

## 7. Hardened Security Controls

The remediated implementation applies the following controls:

- Embedded API credentials are removed.
- Sensitive logging is removed.
- Session credentials are not persisted.
- HTTPS replaces the cleartext endpoint.
- Cleartext network traffic is disabled.
- The custom exported action is removed.
- The JavaScript bridge is removed.
- JavaScript and local access are disabled.
- WebView navigation is host restricted.
- SHA-256 replaces MD5.
- Application backup is disabled.
- Debugging is disabled.
- External-storage permissions are removed.

## 8. OWASP Coverage

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

## 9. Remediation Assurance

The remediation validator confirms both sides of each security control:

1. The expected weakness exists in the vulnerable implementation.
2. The corrective control exists in the remediated implementation.
3. Known insecure patterns are absent from the remediated implementation.
4. Every registered finding has a matching validation control.
5. Reintroduced weaknesses cause automated test failure.

| Validation Result | Count |
|---|---:|
| Passed | 11 |
| Failed | 0 |
| Total | 11 |

## 10. Testing Commands

```bash
python3 scripts/analyze_findings.py
python3 scripts/validate_remediation.py
python3 -m unittest discover -s tests -v
```

## 11. Assessment Limitations

- No production APK was assessed.
- No physical Android device was tested.
- Backend API testing is outside scope.
- Third-party dependencies are not represented.
- Runtime hooking is not represented.
- Server-side TLS configuration was not tested.
- The findings use synthetic source evidence.

## 12. Recommended Next Steps

1. Build and inspect a signed release APK.
2. Run MobSF static and dynamic analysis.
3. Add dependency and secret scanning.
4. Test exported components using ADB.
5. Inspect storage, logs and backup behavior.
6. Test WebView navigation controls.
7. Perform backend API security testing.
8. Integrate all validation into CI/CD.

## 13. Technical Conclusion

The assessment identified 11 Android security findings across seven OWASP MASVS areas.

All 11 represented remediation controls passed automated validation.

The results demonstrate traceability from source evidence through risk classification, secure implementation and evidence-based closure.
