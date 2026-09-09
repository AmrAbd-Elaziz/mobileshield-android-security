#!/usr/bin/env python3

import argparse
import json
from collections import Counter
from pathlib import Path


DEFAULT_FINDINGS = (
    "data/processed/analyzed-findings.json"
)

DEFAULT_VALIDATION = (
    "data/processed/remediation-validation.json"
)

DEFAULT_OUTPUT = (
    "reports/technical/"
    "MOBILE-SECURITY-ASSESSMENT-REPORT.md"
)


SECURITY_IMPACTS = {
    "MS-001": (
        "Embedded credentials can be extracted through "
        "application decompilation or static analysis."
    ),
    "MS-002": (
        "Sensitive log entries may disclose session or "
        "credential information to unauthorized parties."
    ),
    "MS-003": (
        "Plaintext local storage may expose sensitive "
        "values through device access, backup or malware."
    ),
    "MS-004": (
        "Cleartext traffic can be intercepted or modified "
        "by a network-positioned attacker."
    ),
    "MS-005": (
        "An external application may invoke sensitive "
        "functionality without sufficient authorization."
    ),
    "MS-006": (
        "Untrusted WebView content may access native "
        "functionality and retrieve session information."
    ),
    "MS-007": (
        "Unsafe WebView settings increase exposure to "
        "local-resource access and malicious content."
    ),
    "MS-008": (
        "MD5 does not provide suitable collision "
        "resistance for security-sensitive hashing."
    ),
    "MS-009": (
        "Application backups may contain sensitive local "
        "data that can be recovered outside the app."
    ),
    "MS-010": (
        "Debug-enabled builds permit additional runtime "
        "inspection and application manipulation."
    ),
    "MS-011": (
        "Unnecessary permissions increase access to "
        "device data and expand application attack surface."
    ),
}


REMEDIATION_SUMMARIES = {
    "MS-001": (
        "Remove embedded API credentials and keep "
        "privileged secrets on trusted backend systems."
    ),
    "MS-002": (
        "Remove sensitive debug logs and retain only "
        "production-safe operational telemetry."
    ),
    "MS-003": (
        "Avoid persisting session and API credentials; "
        "use Keystore-backed protection when required."
    ),
    "MS-004": (
        "Use HTTPS exclusively and disable cleartext "
        "traffic in Android network configuration."
    ),
    "MS-005": (
        "Remove the unnecessary custom exported action "
        "and do not trust externally supplied auth state."
    ),
    "MS-006": (
        "Remove the JavaScript bridge and do not expose "
        "session information to web content."
    ),
    "MS-007": (
        "Disable unnecessary WebView capabilities and "
        "restrict navigation to the approved HTTPS host."
    ),
    "MS-008": (
        "Replace MD5 with an approved algorithm suitable "
        "for the intended security purpose."
    ),
    "MS-009": (
        "Disable backups or explicitly exclude sensitive "
        "application data."
    ),
    "MS-010": (
        "Disable debugging and validate release-build "
        "configuration through CI/CD."
    ),
    "MS-011": (
        "Remove external-storage permissions that are "
        "not required by application functionality."
    ),
}


def load_json(path):
    with open(path, encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, list):
        raise ValueError(
            f"{path}: expected a JSON array"
        )

    return data


def build_report(findings, validation):
    validation_by_id = {
        result["finding_id"]: result
        for result in validation
    }

    finding_ids = {
        finding["finding_id"]
        for finding in findings
    }

    if finding_ids != set(validation_by_id):
        raise ValueError(
            "Finding and validation IDs do not match"
        )

    severity_counts = Counter(
        finding["severity"]
        for finding in findings
    )

    passed = sum(
        result["validation_status"] == "Passed"
        for result in validation
    )

    lines = [
        "# MobileShield Technical Security Assessment",
        "",
        "## 1. Report Scope",
        "",
        (
            "This report documents a source-based "
            "security assessment of the synthetic "
            "MobileShield Android application."
        ),
        "",
        (
            "The assessment compares an intentionally "
            "vulnerable implementation with a hardened "
            "reference implementation and validates "
            "remediation through automated checks."
        ),
        "",
        (
            "> All application data, endpoints, "
            "credentials and findings are synthetic and "
            "intended exclusively for authorized "
            "security training."
        ),
        "",
        "## 2. Evidence Summary",
        "",
        "| Evidence Metric | Result |",
        "|---|---:|",
        f"| Findings analyzed | {len(findings)} |",
        (
            "| Critical findings | "
            f"{severity_counts.get('Critical', 0)} |"
        ),
        (
            "| High findings | "
            f"{severity_counts.get('High', 0)} |"
        ),
        (
            "| Medium findings | "
            f"{severity_counts.get('Medium', 0)} |"
        ),
        (
            "| Remediation controls passed | "
            f"{passed} |"
        ),
        (
            "| Remediation controls failed | "
            f"{len(validation) - passed} |"
        ),
        "",
        "## 3. Assessment Components",
        "",
        "| Component | Location |",
        "|---|---|",
        (
            "| Vulnerable Android implementation "
            "| `app/vulnerable/` |"
        ),
        (
            "| Hardened Android implementation "
            "| `app/remediated/` |"
        ),
        (
            "| Source finding register "
            "| `data/raw/mobile-security-findings.json` |"
        ),
        (
            "| Prioritized findings "
            "| `data/processed/analyzed-findings.json` |"
        ),
        (
            "| Remediation evidence "
            "| `data/processed/remediation-validation.json` |"
        ),
        "",
        "## 4. Finding Register",
        "",
        (
            "| ID | Finding | Severity | Category | "
            "MASVS | MASWE | SLA | Status |"
        ),
        "|---|---|---|---|---|---|---:|---|",
    ]

    for finding in findings:
        result = validation_by_id[
            finding["finding_id"]
        ]

        lines.append(
            f"| {finding['finding_id']} "
            f"| {finding['title']} "
            f"| {finding['severity']} "
            f"| {finding['category']} "
            f"| {finding['masvs_group']} "
            f"| {finding['maswe_id']} "
            f"| {finding['target_sla']} "
            f"| {result['disposition']} |"
        )

    lines.extend(
        [
            "",
            "## 5. Detailed Technical Findings",
            "",
        ]
    )

    for index, finding in enumerate(
        findings,
        start=1,
    ):
        finding_id = finding["finding_id"]
        result = validation_by_id[finding_id]

        lines.extend(
            [
                (
                    f"### 5.{index} {finding_id} — "
                    f"{finding['title']}"
                ),
                "",
                f"**Severity:** {finding['severity']}",
                "",
                f"**Category:** {finding['category']}",
                "",
                (
                    f"**Standards mapping:** "
                    f"{finding['masvs_group']} / "
                    f"{finding['maswe_id']}"
                ),
                "",
                (
                    f"**Affected file:** "
                    f"`{finding['file_path']}`"
                ),
                "",
                f"**Source:** {finding['source']}",
                "",
                "**Evidence:**",
                "",
                f"> `{finding['evidence']}`",
                "",
                "**Security impact:**",
                "",
                SECURITY_IMPACTS[finding_id],
                "",
                "**Recommended remediation:**",
                "",
                REMEDIATION_SUMMARIES[finding_id],
                "",
                "**Implemented control:**",
                "",
                result["control"],
                "",
                (
                    f"**Validation status:** "
                    f"{result['validation_status']}"
                ),
                "",
                (
                    f"**Final disposition:** "
                    f"{result['disposition']}"
                ),
                "",
            ]
        )

    lines.extend(
        [
            "## 6. Vulnerable Attack Surface",
            "",
            (
                "The vulnerable implementation contains "
                "multiple connected weaknesses:"
            ),
            "",
            (
                "- An external application can invoke "
                "the custom exported activity action."
            ),
            (
                "- Intent-supplied account and session "
                "values are accepted without validation."
            ),
            (
                "- Sensitive values are logged and "
                "stored in plaintext preferences."
            ),
            (
                "- Cleartext HTTP content is loaded into "
                "an unsafe WebView."
            ),
            (
                "- JavaScript can call a native bridge "
                "that exposes session information."
            ),
            (
                "- Local file and content access are "
                "enabled inside the WebView."
            ),
            (
                "- Debugging, backup and unnecessary "
                "permissions expand device-level exposure."
            ),
            "",
            "## 7. Hardened Security Controls",
            "",
            (
                "The remediated implementation applies "
                "the following controls:"
            ),
            "",
            "- Embedded API credentials are removed.",
            "- Sensitive logging is removed.",
            "- Session credentials are not persisted.",
            "- HTTPS replaces the cleartext endpoint.",
            "- Cleartext network traffic is disabled.",
            "- The custom exported action is removed.",
            "- The JavaScript bridge is removed.",
            "- JavaScript and local access are disabled.",
            "- WebView navigation is host restricted.",
            "- SHA-256 replaces MD5.",
            "- Application backup is disabled.",
            "- Debugging is disabled.",
            "- External-storage permissions are removed.",
            "",
            "## 8. OWASP Coverage",
            "",
            "| MASVS Group | Findings |",
            "|---|---:|",
        ]
    )

    group_counts = Counter(
        finding["masvs_group"]
        for finding in findings
    )

    for group in [
        "MASVS-STORAGE",
        "MASVS-CRYPTO",
        "MASVS-AUTH",
        "MASVS-NETWORK",
        "MASVS-PLATFORM",
        "MASVS-CODE",
        "MASVS-RESILIENCE",
        "MASVS-PRIVACY",
    ]:
        lines.append(
            f"| {group} "
            f"| {group_counts.get(group, 0)} |"
        )

    lines.extend(
        [
            "",
            "## 9. Remediation Assurance",
            "",
            (
                "The remediation validator confirms both "
                "sides of each security control:"
            ),
            "",
            (
                "1. The expected weakness exists in the "
                "vulnerable implementation."
            ),
            (
                "2. The corrective control exists in the "
                "remediated implementation."
            ),
            (
                "3. Known insecure patterns are absent "
                "from the remediated implementation."
            ),
            (
                "4. Every registered finding has a "
                "matching validation control."
            ),
            (
                "5. Reintroduced weaknesses cause "
                "automated test failure."
            ),
            "",
            "| Validation Result | Count |",
            "|---|---:|",
            f"| Passed | {passed} |",
            f"| Failed | {len(validation) - passed} |",
            f"| Total | {len(validation)} |",
            "",
            "## 10. Testing Commands",
            "",
            "```bash",
            "python3 scripts/analyze_findings.py",
            "python3 scripts/validate_remediation.py",
            "python3 -m unittest discover -s tests -v",
            "```",
            "",
            "## 11. Assessment Limitations",
            "",
            "- No production APK was assessed.",
            "- No physical Android device was tested.",
            "- Backend API testing is outside scope.",
            "- Third-party dependencies are not represented.",
            "- Runtime hooking is not represented.",
            "- Server-side TLS configuration was not tested.",
            "- The findings use synthetic source evidence.",
            "",
            "## 12. Recommended Next Steps",
            "",
            "1. Build and inspect a signed release APK.",
            "2. Run MobSF static and dynamic analysis.",
            "3. Add dependency and secret scanning.",
            "4. Test exported components using ADB.",
            "5. Inspect storage, logs and backup behavior.",
            "6. Test WebView navigation controls.",
            "7. Perform backend API security testing.",
            "8. Integrate all validation into CI/CD.",
            "",
            "## 13. Technical Conclusion",
            "",
            (
                f"The assessment identified "
                f"{len(findings)} Android security "
                "findings across seven OWASP MASVS areas."
            ),
            "",
            (
                f"All {passed} represented remediation "
                "controls passed automated validation."
            ),
            "",
            (
                "The results demonstrate traceability "
                "from source evidence through risk "
                "classification, secure implementation "
                "and evidence-based closure."
            ),
            "",
        ]
    )

    return "\n".join(lines)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description=(
            "Generate the MobileShield technical "
            "security assessment report."
        )
    )

    parser.add_argument(
        "--findings",
        default=DEFAULT_FINDINGS,
    )

    parser.add_argument(
        "--validation",
        default=DEFAULT_VALIDATION,
    )

    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT,
    )

    return parser.parse_args()


def main():
    args = parse_arguments()

    findings = load_json(args.findings)
    validation = load_json(args.validation)

    report = build_report(
        findings,
        validation,
    )

    output = Path(args.output)
    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output.write_text(
        report,
        encoding="utf-8",
    )

    print(f"Findings included: {len(findings)}")
    print(
        "Validation records included: "
        f"{len(validation)}"
    )
    print(f"Technical report: {output}")


if __name__ == "__main__":
    main()