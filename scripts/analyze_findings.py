#!/usr/bin/env python3

import argparse
import json
from collections import Counter
from pathlib import Path


SEVERITY_SCORES = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Informational": 0,
}

REMEDIATION_SLAS = {
    "Critical": "2 days",
    "High": "7 days",
    "Medium": "30 days",
    "Low": "90 days",
    "Informational": "Monitor",
}

REQUIRED_FIELDS = {
    "finding_id",
    "title",
    "category",
    "severity",
    "source",
    "file_path",
    "evidence",
    "masvs_group",
    "maswe_id",
    "status",
}


def load_findings(path):
    with open(path, encoding="utf-8") as file:
        findings = json.load(file)

    if not isinstance(findings, list):
        raise ValueError("Findings file must contain a JSON array")

    return findings


def validate_finding(finding, position):
    missing_fields = sorted(REQUIRED_FIELDS - finding.keys())

    if missing_fields:
        raise ValueError(
            f"Finding {position}: missing fields: "
            f"{', '.join(missing_fields)}"
        )

    empty_fields = sorted(
        field
        for field in REQUIRED_FIELDS
        if not str(finding[field]).strip()
    )

    if empty_fields:
        raise ValueError(
            f"{finding['finding_id']}: empty fields: "
            f"{', '.join(empty_fields)}"
        )

    severity = finding["severity"]

    if severity not in SEVERITY_SCORES:
        raise ValueError(
            f"{finding['finding_id']}: unsupported severity "
            f"{severity!r}"
        )

    finding_id = finding["finding_id"]

    if not finding_id.startswith("MS-"):
        raise ValueError(
            f"{finding_id}: finding ID must start with MS-"
        )

    if not finding["maswe_id"].startswith("MASWE-"):
        raise ValueError(
            f"{finding_id}: invalid MASWE identifier"
        )


def validate_unique_ids(findings):
    identifiers = [
        finding["finding_id"]
        for finding in findings
    ]

    duplicates = sorted(
        finding_id
        for finding_id, count in Counter(identifiers).items()
        if count > 1
    )

    if duplicates:
        raise ValueError(
            "Duplicate finding IDs: "
            + ", ".join(duplicates)
        )


def enrich_finding(finding):
    enriched = dict(finding)
    severity = finding["severity"]

    enriched["severity_score"] = SEVERITY_SCORES[severity]
    enriched["target_sla"] = REMEDIATION_SLAS[severity]
    enriched["actionable"] = severity != "Informational"

    return enriched


def analyze_findings(input_path, output_path):
    findings = load_findings(input_path)

    for position, finding in enumerate(findings, start=1):
        validate_finding(finding, position)

    validate_unique_ids(findings)

    processed = [
        enrich_finding(finding)
        for finding in findings
    ]

    processed.sort(
        key=lambda finding: (
            -finding["severity_score"],
            finding["finding_id"],
        )
    )

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("w", encoding="utf-8") as file:
        json.dump(
            processed,
            file,
            indent=2,
            ensure_ascii=False,
        )
        file.write("\n")

    return processed


def parse_arguments():
    parser = argparse.ArgumentParser(
        description=(
            "Validate and prioritize MobileShield "
            "Android security findings."
        )
    )

    parser.add_argument(
        "--input",
        default="data/raw/mobile-security-findings.json",
        help="Path to the raw findings JSON file",
    )

    parser.add_argument(
        "--output",
        default="data/processed/analyzed-findings.json",
        help="Path for processed findings",
    )

    return parser.parse_args()


def main():
    args = parse_arguments()

    findings = analyze_findings(
        args.input,
        args.output,
    )

    severity_counts = Counter(
        finding["severity"]
        for finding in findings
    )

    print(f"Findings analyzed: {len(findings)}")

    for severity in SEVERITY_SCORES:
        print(
            f"{severity}: "
            f"{severity_counts.get(severity, 0)}"
        )

    print(f"Output: {args.output}")

    for finding in findings:
        print(
            f"{finding['finding_id']} | "
            f"{finding['severity']:<13} | "
            f"{finding['target_sla']:<7} | "
            f"{finding['title']}"
        )


if __name__ == "__main__":
    main()