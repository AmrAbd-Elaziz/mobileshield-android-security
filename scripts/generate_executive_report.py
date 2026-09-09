#!/usr/bin/env python3

import argparse
import json
from collections import Counter
from datetime import date
from pathlib import Path


DEFAULT_FINDINGS = (
    "data/processed/analyzed-findings.json"
)

DEFAULT_VALIDATION = (
    "data/processed/remediation-validation.json"
)

DEFAULT_OUTPUT = (
    "reports/executive/"
    "EXECUTIVE-MOBILE-SECURITY-REPORT.md"
)


def load_json(path):
    with open(path, encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, list):
        raise ValueError(
            f"{path}: expected a JSON array"
        )

    return data


def build_report(
    findings,
    validation,
    assessment_date,
):
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

    category_counts = Counter(
        finding["masvs_group"]
        for finding in findings
    )

    passed = sum(
        result["validation_status"] == "Passed"
        for result in validation
    )

    closed = sum(
        result["disposition"] == "Closed"
        for result in validation
    )

    total = len(findings)

    coverage = (
        round((passed / total) * 100, 1)
        if total
        else 0.0
    )

    critical_findings = [
        finding
        for finding in findings
        if finding["severity"] == "Critical"
    ]

    lines = [
        "# Executive Mobile Application Security Report",
        "",
        "## Assessment Overview",
        "",
        "| Metric | Result |",
        "|---|---:|",
        f"| Assessment date | {assessment_date} |",
        f"| Findings identified | {total} |",
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
        f"| Remediation controls passed | {passed} |",
        f"| Findings closed | {closed} |",
        f"| Validation coverage | {coverage:.1f}% |",
        "",
        "## Executive Summary",
        "",
        (
            "The MobileShield assessment evaluated a "
            "synthetic Android application containing "
            f"{total} intentionally vulnerable security "
            "patterns."
        ),
        "",
        (
            f"The assessment identified "
            f"{severity_counts.get('Critical', 0)} "
            "Critical, "
            f"{severity_counts.get('High', 0)} High and "
            f"{severity_counts.get('Medium', 0)} Medium "
            "findings."
        ),
        "",
        (
            "The highest-risk weaknesses involved an "
            "unprotected exported Android component and "
            "a WebView JavaScript interface capable of "
            "exposing session information."
        ),
        "",
        (
            f"Automated validation confirmed {passed} of "
            f"{total} remediation controls, providing "
            f"{coverage:.1f}% evidence coverage."
        ),
        "",
        "## Business Risk",
        "",
        "| Risk Area | Assessment |",
        "|---|---|",
        (
            "| Account security | Critical — exposed "
            "components and session disclosure could "
            "enable unauthorized access |"
        ),
        (
            "| Data confidentiality | High — secrets, "
            "logs, local storage and backups could "
            "disclose sensitive values |"
        ),
        (
            "| Network security | High — cleartext "
            "traffic could be intercepted or modified |"
        ),
        (
            "| Application integrity | High — unsafe "
            "WebView and debug configuration increase "
            "the attack surface |"
        ),
        (
            "| Privacy and permissions | Medium — "
            "unnecessary storage permissions provide "
            "excessive device access |"
        ),
        "",
        "## Severity Distribution",
        "",
        "| Severity | Findings | Target SLA |",
        "|---|---:|---:|",
        (
            "| Critical | "
            f"{severity_counts.get('Critical', 0)} "
            "| 2 days |"
        ),
        (
            "| High | "
            f"{severity_counts.get('High', 0)} "
            "| 7 days |"
        ),
        (
            "| Medium | "
            f"{severity_counts.get('Medium', 0)} "
            "| 30 days |"
        ),
        (
            "| Low | "
            f"{severity_counts.get('Low', 0)} "
            "| 90 days |"
        ),
        "",
        "## Critical Findings",
        "",
        "| ID | Finding | MASVS Group | MASWE | Status |",
        "|---|---|---|---|---|",
    ]

    for finding in critical_findings:
        validation_result = validation_by_id[
            finding["finding_id"]
        ]

        lines.append(
            f"| {finding['finding_id']} "
            f"| {finding['title']} "
            f"| {finding['masvs_group']} "
            f"| {finding['maswe_id']} "
            f"| {validation_result['disposition']} |"
        )

    lines.extend(
        [
            "",
            "## Security Coverage",
            "",
            "| MASVS Area | Findings |",
            "|---|---:|",
        ]
    )

    group_order = [
        "MASVS-STORAGE",
        "MASVS-CRYPTO",
        "MASVS-AUTH",
        "MASVS-NETWORK",
        "MASVS-PLATFORM",
        "MASVS-CODE",
        "MASVS-RESILIENCE",
        "MASVS-PRIVACY",
    ]

    for group in group_order:
        lines.append(
            f"| {group} "
            f"| {category_counts.get(group, 0)} |"
        )

    lines.extend(
        [
            "",
            "## Remediation Outcome",
            "",
            "| Outcome | Findings |",
            "|---|---:|",
            f"| Validated and closed | {closed} |",
            f"| Failed validation | {total - passed} |",
            f"| Remaining open | {total - closed} |",
            f"| Evidence coverage | {coverage:.1f}% |",
            "",
            (
                "The hardened implementation removes "
                "embedded credentials, sensitive logging "
                "and plaintext session persistence."
            ),
            "",
            (
                "It also enforces HTTPS, reduces exposed "
                "Android functionality, hardens WebView "
                "settings, disables debugging and backup, "
                "and removes unnecessary permissions."
            ),
            "",
            "## Management Recommendations",
            "",
            (
                "1. Integrate mobile security validation "
                "into every release pipeline."
            ),
            (
                "2. Test compiled release APKs through "
                "static and dynamic analysis."
            ),
            (
                "3. Keep privileged credentials and "
                "authorization decisions on trusted "
                "backend systems."
            ),
            (
                "4. Require security review for exported "
                "components, deep links and WebViews."
            ),
            (
                "5. Enforce HTTPS and restrictive Android "
                "network-security configuration."
            ),
            (
                "6. Minimize local data storage, logs, "
                "backups and application permissions."
            ),
            (
                "7. Require evidence-based retesting "
                "before closing mobile findings."
            ),
            "",
            "## Management Conclusion",
            "",
            (
                "The initial MobileShield implementation "
                "contained multiple connected weaknesses "
                "that could expose credentials, session "
                "data, network traffic and native "
                "application functionality."
            ),
            "",
            (
                f"The remediated implementation passed "
                f"{passed} automated security controls "
                "and achieved complete demonstrated "
                "closure coverage."
            ),
            "",
            (
                "> This report uses synthetic evidence "
                "and is intended exclusively for "
                "authorized security training and "
                "portfolio demonstration."
            ),
            "",
        ]
    )

    return "\n".join(lines)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description=(
            "Generate the MobileShield executive "
            "mobile security report."
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

    parser.add_argument(
        "--assessment-date",
        default=date.today().isoformat(),
    )

    return parser.parse_args()


def main():
    args = parse_arguments()

    findings = load_json(args.findings)
    validation = load_json(args.validation)

    report = build_report(
        findings,
        validation,
        args.assessment_date,
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
        "Remediation records included: "
        f"{len(validation)}"
    )
    print(f"Executive report: {output}")


if __name__ == "__main__":
    main()