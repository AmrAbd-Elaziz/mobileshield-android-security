#!/usr/bin/env python3

import argparse
import json
from pathlib import Path


DEFAULT_FINDINGS = Path(
    "data/raw/mobile-security-findings.json"
)

VULNERABLE_ROOT = Path(
    "app/vulnerable/src/main"
)

REMEDIATED_ROOT = Path(
    "app/remediated/src/main"
)

VULNERABLE_ACTIVITY = (
    VULNERABLE_ROOT
    / "java/com/mobileshield/MainActivity.kt"
)

REMEDIATED_ACTIVITY = (
    REMEDIATED_ROOT
    / "java/com/mobileshield/MainActivity.kt"
)

VULNERABLE_MANIFEST = (
    VULNERABLE_ROOT / "AndroidManifest.xml"
)

REMEDIATED_MANIFEST = (
    REMEDIATED_ROOT / "AndroidManifest.xml"
)

VULNERABLE_NETWORK_CONFIG = (
    VULNERABLE_ROOT
    / "res/xml/network_security_config.xml"
)

REMEDIATED_NETWORK_CONFIG = (
    REMEDIATED_ROOT
    / "res/xml/network_security_config.xml"
)


def read_text(path):
    if not path.is_file():
        raise FileNotFoundError(
            f"Required file not found: {path}"
        )

    return path.read_text(encoding="utf-8")


def contains_all(content, patterns):
    return all(
        pattern in content
        for pattern in patterns
    )


def contains_none(content, patterns):
    return all(
        pattern not in content
        for pattern in patterns
    )


def build_checks():
    vulnerable_activity = read_text(
        VULNERABLE_ACTIVITY
    )
    remediated_activity = read_text(
        REMEDIATED_ACTIVITY
    )

    vulnerable_manifest = read_text(
        VULNERABLE_MANIFEST
    )
    remediated_manifest = read_text(
        REMEDIATED_MANIFEST
    )

    vulnerable_network = read_text(
        VULNERABLE_NETWORK_CONFIG
    )
    remediated_network = read_text(
        REMEDIATED_NETWORK_CONFIG
    )

    return {
        "MS-001": {
            "control": "Hardcoded API key removed",
            "vulnerable_evidence": contains_all(
                vulnerable_activity,
                ["API_KEY"],
            ),
            "remediation_verified": contains_none(
                remediated_activity,
                ["API_KEY"],
            ),
        },
        "MS-002": {
            "control": "Sensitive debug logging removed",
            "vulnerable_evidence": contains_all(
                vulnerable_activity,
                ["Log.d"],
            ),
            "remediation_verified": contains_none(
                remediated_activity,
                ["Log.d", "android.util.Log"],
            ),
        },
        "MS-003": {
            "control": (
                "Sensitive plaintext preference "
                "storage removed"
            ),
            "vulnerable_evidence": contains_all(
                vulnerable_activity,
                [
                    'putString("session_token"',
                    'putString("api_key"',
                ],
            ),
            "remediation_verified": contains_none(
                remediated_activity,
                [
                    'putString("session_token"',
                    'putString("api_key"',
                    "getSharedPreferences",
                ],
            ),
        },
        "MS-004": {
            "control": (
                "HTTPS enforced and cleartext "
                "traffic disabled"
            ),
            "vulnerable_evidence": contains_all(
                vulnerable_activity
                + vulnerable_manifest
                + vulnerable_network,
                [
                    "http://api.mobileshield.test",
                    'usesCleartextTraffic="true"',
                    'cleartextTrafficPermitted="true"',
                ],
            ),
            "remediation_verified": (
                contains_all(
                    remediated_activity
                    + remediated_manifest
                    + remediated_network,
                    [
                        "https://api.mobileshield.test",
                        'usesCleartextTraffic="false"',
                        'cleartextTrafficPermitted="false"',
                    ],
                )
                and contains_none(
                    remediated_activity,
                    ["http://api.mobileshield.test"],
                )
            ),
        },
        "MS-005": {
            "control": (
                "Unprotected custom intent "
                "entry point removed"
            ),
            "vulnerable_evidence": contains_all(
                vulnerable_manifest,
                [
                    "com.mobileshield.OPEN_ACCOUNT",
                    'android:exported="true"',
                ],
            ),
            "remediation_verified": contains_none(
                remediated_manifest,
                ["com.mobileshield.OPEN_ACCOUNT"],
            ),
        },
        "MS-006": {
            "control": (
                "JavaScript interface exposing "
                "session data removed"
            ),
            "vulnerable_evidence": contains_all(
                vulnerable_activity,
                [
                    "addJavascriptInterface",
                    "getSessionToken",
                ],
            ),
            "remediation_verified": contains_none(
                remediated_activity,
                [
                    "addJavascriptInterface",
                    "getSessionToken",
                    "@JavascriptInterface",
                ],
            ),
        },
        "MS-007": {
            "control": (
                "WebView local and content access "
                "disabled"
            ),
            "vulnerable_evidence": contains_all(
                vulnerable_activity,
                [
                    "allowFileAccess = true",
                    "allowContentAccess = true",
                    (
                        "allowUniversalAccessFrom"
                        "FileURLs = true"
                    ),
                ],
            ),
            "remediation_verified": contains_all(
                remediated_activity,
                [
                    "javaScriptEnabled = false",
                    "allowFileAccess = false",
                    "allowContentAccess = false",
                    (
                        "allowUniversalAccessFrom"
                        "FileURLs = false"
                    ),
                ],
            ),
        },
        "MS-008": {
            "control": "MD5 replaced with SHA-256",
            "vulnerable_evidence": contains_all(
                vulnerable_activity,
                ['getInstance("MD5")'],
            ),
            "remediation_verified": (
                contains_all(
                    remediated_activity,
                    ['getInstance("SHA-256")'],
                )
                and contains_none(
                    remediated_activity,
                    ['getInstance("MD5")'],
                )
            ),
        },
        "MS-009": {
            "control": "Application backups disabled",
            "vulnerable_evidence": contains_all(
                vulnerable_manifest,
                ['android:allowBackup="true"'],
            ),
            "remediation_verified": contains_all(
                remediated_manifest,
                ['android:allowBackup="false"'],
            ),
        },
        "MS-010": {
            "control": "Debuggable mode disabled",
            "vulnerable_evidence": contains_all(
                vulnerable_manifest,
                ['android:debuggable="true"'],
            ),
            "remediation_verified": contains_all(
                remediated_manifest,
                ['android:debuggable="false"'],
            ),
        },
        "MS-011": {
            "control": (
                "Unnecessary external-storage "
                "permissions removed"
            ),
            "vulnerable_evidence": contains_all(
                vulnerable_manifest,
                [
                    "READ_EXTERNAL_STORAGE",
                    "WRITE_EXTERNAL_STORAGE",
                ],
            ),
            "remediation_verified": contains_none(
                remediated_manifest,
                [
                    "READ_EXTERNAL_STORAGE",
                    "WRITE_EXTERNAL_STORAGE",
                ],
            ),
        },
    }


def validate_remediation(
    findings_path,
    output_path,
):
    with open(
        findings_path,
        encoding="utf-8",
    ) as file:
        findings = json.load(file)

    if not isinstance(findings, list):
        raise ValueError(
            "Findings file must contain a JSON array"
        )

    checks = build_checks()
    finding_ids = {
        finding["finding_id"]
        for finding in findings
    }

    if finding_ids != set(checks):
        missing_checks = sorted(
            finding_ids - set(checks)
        )
        unknown_checks = sorted(
            set(checks) - finding_ids
        )

        raise ValueError(
            "Finding/check mismatch. "
            f"Missing checks: {missing_checks}; "
            f"unknown checks: {unknown_checks}"
        )

    results = []

    for finding in findings:
        finding_id = finding["finding_id"]
        check = checks[finding_id]

        passed = (
            check["vulnerable_evidence"]
            and check["remediation_verified"]
        )

        results.append(
            {
                "finding_id": finding_id,
                "title": finding["title"],
                "severity": finding["severity"],
                "control": check["control"],
                "vulnerable_evidence_confirmed": (
                    check["vulnerable_evidence"]
                ),
                "remediation_verified": (
                    check["remediation_verified"]
                ),
                "validation_status": (
                    "Passed" if passed else "Failed"
                ),
                "disposition": (
                    "Closed" if passed else "Open"
                ),
            }
        )

    output = Path(output_path)
    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            results,
            file,
            indent=2,
            ensure_ascii=False,
        )
        file.write("\n")

    failed = [
        result["finding_id"]
        for result in results
        if result["validation_status"] != "Passed"
    ]

    if failed:
        raise ValueError(
            "Remediation validation failed: "
            + ", ".join(failed)
        )

    return results


def parse_arguments():
    parser = argparse.ArgumentParser(
        description=(
            "Validate MobileShield remediation "
            "controls against vulnerable code."
        )
    )

    parser.add_argument(
        "--findings",
        default=str(DEFAULT_FINDINGS),
    )

    parser.add_argument(
        "--output",
        default=(
            "data/processed/"
            "remediation-validation.json"
        ),
    )

    return parser.parse_args()


def main():
    args = parse_arguments()

    results = validate_remediation(
        args.findings,
        args.output,
    )

    passed = sum(
        result["validation_status"] == "Passed"
        for result in results
    )

    print("Remediation validation passed")
    print(f"Controls validated: {len(results)}")
    print(f"Passed: {passed}")
    print(f"Failed: {len(results) - passed}")
    print(f"Output: {args.output}")

    for result in results:
        print(
            f"{result['finding_id']} | "
            f"{result['validation_status']:<6} | "
            f"{result['control']}"
        )


if __name__ == "__main__":
    main()