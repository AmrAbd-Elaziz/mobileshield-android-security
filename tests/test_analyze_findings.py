import json
import tempfile
import unittest
from pathlib import Path

from scripts.analyze_findings import (
    analyze_findings,
    enrich_finding,
    validate_finding,
    validate_unique_ids,
)


def sample_finding(
    finding_id="MS-001",
    severity="High",
):
    return {
        "finding_id": finding_id,
        "title": "Synthetic Android Security Finding",
        "category": "Mobile Security",
        "severity": severity,
        "source": "Unit Test",
        "file_path": "app/TestActivity.kt",
        "evidence": "Synthetic test evidence",
        "masvs_group": "MASVS-STORAGE",
        "maswe_id": "MASWE-0001",
        "status": "Open",
    }


class FindingValidationTests(unittest.TestCase):

    def test_valid_finding_is_accepted(self):
        validate_finding(sample_finding(), 1)

    def test_missing_required_field_is_rejected(self):
        finding = sample_finding()
        del finding["evidence"]

        with self.assertRaisesRegex(
            ValueError,
            "missing fields: evidence",
        ):
            validate_finding(finding, 1)

    def test_empty_required_field_is_rejected(self):
        finding = sample_finding()
        finding["title"] = " "

        with self.assertRaisesRegex(
            ValueError,
            "empty fields: title",
        ):
            validate_finding(finding, 1)

    def test_unknown_severity_is_rejected(self):
        finding = sample_finding(severity="Severe")

        with self.assertRaisesRegex(
            ValueError,
            "unsupported severity",
        ):
            validate_finding(finding, 1)

    def test_invalid_finding_id_is_rejected(self):
        finding = sample_finding(finding_id="ANDROID-001")

        with self.assertRaisesRegex(
            ValueError,
            "must start with MS-",
        ):
            validate_finding(finding, 1)

    def test_invalid_maswe_id_is_rejected(self):
        finding = sample_finding()
        finding["maswe_id"] = "OWASP-0001"

        with self.assertRaisesRegex(
            ValueError,
            "invalid MASWE identifier",
        ):
            validate_finding(finding, 1)

    def test_duplicate_ids_are_rejected(self):
        findings = [
            sample_finding("MS-001"),
            sample_finding("MS-001"),
        ]

        with self.assertRaisesRegex(
            ValueError,
            "Duplicate finding IDs: MS-001",
        ):
            validate_unique_ids(findings)


class FindingEnrichmentTests(unittest.TestCase):

    def test_critical_finding_receives_two_day_sla(self):
        finding = enrich_finding(
            sample_finding(
                finding_id="MS-005",
                severity="Critical",
            )
        )

        self.assertEqual(finding["severity_score"], 4)
        self.assertEqual(finding["target_sla"], "2 days")
        self.assertTrue(finding["actionable"])

    def test_medium_finding_receives_thirty_day_sla(self):
        finding = enrich_finding(
            sample_finding(severity="Medium")
        )

        self.assertEqual(finding["severity_score"], 2)
        self.assertEqual(finding["target_sla"], "30 days")

    def test_informational_finding_is_not_actionable(self):
        finding = enrich_finding(
            sample_finding(severity="Informational")
        )

        self.assertEqual(finding["severity_score"], 0)
        self.assertEqual(finding["target_sla"], "Monitor")
        self.assertFalse(finding["actionable"])


class FindingAnalysisTests(unittest.TestCase):

    def test_findings_are_sorted_by_severity(self):
        findings = [
            sample_finding("MS-003", "Medium"),
            sample_finding("MS-001", "High"),
            sample_finding("MS-002", "Critical"),
        ]

        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "input.json"
            output_path = Path(directory) / "output.json"

            input_path.write_text(
                json.dumps(findings),
                encoding="utf-8",
            )

            processed = analyze_findings(
                input_path,
                output_path,
            )

            self.assertEqual(
                [
                    finding["finding_id"]
                    for finding in processed
                ],
                ["MS-002", "MS-001", "MS-003"],
            )

            self.assertTrue(output_path.exists())

    def test_non_array_input_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "input.json"
            output_path = Path(directory) / "output.json"

            input_path.write_text(
                json.dumps({"findings": []}),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                ValueError,
                "must contain a JSON array",
            ):
                analyze_findings(
                    input_path,
                    output_path,
                )


if __name__ == "__main__":
    unittest.main()