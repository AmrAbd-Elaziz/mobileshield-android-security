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

DEFAULT_OUTPUT = "dashboard/data.json"


def load_json(path):
    with open(path, encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, list):
        raise ValueError(
            f"{path}: expected a JSON array"
        )

    return data


def generate_dashboard_data(
    findings_path,
    validation_path,
    output_path,
    assessment_date,
):
    findings = load_json(findings_path)
    validation = load_json(validation_path)

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

    masvs_counts = Counter(
        finding["masvs_group"]
        for finding in findings
    )

    category_counts = Counter(
        finding["category"]
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

    dashboard_findings = []

    for finding in findings:
        result = validation_by_id[
            finding["finding_id"]
        ]

        dashboard_findings.append(
            {
                "finding_id": finding["finding_id"],
                "title": finding["title"],
                "category": finding["category"],
                "severity": finding["severity"],
                "severity_score": (
                    finding["severity_score"]
                ),
                "target_sla": finding["target_sla"],
                "masvs_group": (
                    finding["masvs_group"]
                ),
                "maswe_id": finding["maswe_id"],
                "file_path": finding["file_path"],
                "evidence": finding["evidence"],
                "control": result["control"],
                "validation_status": (
                    result["validation_status"]
                ),
                "disposition": (
                    result["disposition"]
                ),
            }
        )

    data = {
        "project": "MobileShield",
        "subtitle": (
            "Android Application Security Lab"
        ),
        "assessment_date": assessment_date,
        "metrics": {
            "total_findings": total,
            "critical_findings": (
                severity_counts.get("Critical", 0)
            ),
            "high_findings": (
                severity_counts.get("High", 0)
            ),
            "medium_findings": (
                severity_counts.get("Medium", 0)
            ),
            "remediation_controls": len(validation),
            "controls_passed": passed,
            "closed_findings": closed,
            "validation_coverage": coverage,
            "automated_tests": 18,
            "masvs_areas_covered": sum(
                count > 0
                for count in masvs_counts.values()
            ),
        },
        "severity_distribution": {
            severity: severity_counts.get(
                severity,
                0,
            )
            for severity in [
                "Critical",
                "High",
                "Medium",
                "Low",
                "Informational",
            ]
        },
        "masvs_distribution": {
            group: masvs_counts.get(group, 0)
            for group in [
                "MASVS-STORAGE",
                "MASVS-CRYPTO",
                "MASVS-AUTH",
                "MASVS-NETWORK",
                "MASVS-PLATFORM",
                "MASVS-CODE",
                "MASVS-RESILIENCE",
                "MASVS-PRIVACY",
            ]
        },
        "category_distribution": dict(
            sorted(category_counts.items())
        ),
        "security_flow": [
            {
                "stage": "Threat Model",
                "description": (
                    "Identify assets, entry points "
                    "and trust boundaries."
                ),
            },
            {
                "stage": "Source Review",
                "description": (
                    "Locate insecure Android and "
                    "Kotlin patterns."
                ),
            },
            {
                "stage": "Risk Mapping",
                "description": (
                    "Assign severity, SLA, MASVS "
                    "and MASWE references."
                ),
            },
            {
                "stage": "Remediation",
                "description": (
                    "Implement a hardened Android "
                    "reference version."
                ),
            },
            {
                "stage": "Validation",
                "description": (
                    "Verify every security control "
                    "and prevent regression."
                ),
            },
        ],
        "findings": dashboard_findings,
    }

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
            data,
            file,
            indent=2,
            ensure_ascii=False,
        )
        file.write("\n")

    return data


def parse_arguments():
    parser = argparse.ArgumentParser(
        description=(
            "Generate MobileShield interactive "
            "dashboard data."
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

    data = generate_dashboard_data(
        args.findings,
        args.validation,
        args.output,
        args.assessment_date,
    )

    print(
        "Dashboard findings: "
        f"{data['metrics']['total_findings']}"
    )
    print(
        "Critical findings: "
        f"{data['metrics']['critical_findings']}"
    )
    print(
        "Controls passed: "
        f"{data['metrics']['controls_passed']}"
    )
    print(
        "Validation coverage: "
        f"{data['metrics']['validation_coverage']}%"
    )
    print(f"Dashboard data: {args.output}")


if __name__ == "__main__":
    main()