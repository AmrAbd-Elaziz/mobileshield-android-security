import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import scripts.validate_remediation as remediation


class RemediationCheckTests(unittest.TestCase):

    def test_all_eleven_controls_pass(self):
        checks = remediation.build_checks()

        self.assertEqual(len(checks), 11)

        for finding_id, check in checks.items():
            with self.subTest(finding_id=finding_id):
                self.assertTrue(
                    check["vulnerable_evidence"]
                )
                self.assertTrue(
                    check["remediation_verified"]
                )

    def test_check_ids_match_source_findings(self):
        with open(
            "data/raw/mobile-security-findings.json",
            encoding="utf-8",
        ) as file:
            findings = json.load(file)

        finding_ids = {
            finding["finding_id"]
            for finding in findings
        }

        self.assertEqual(
            finding_ids,
            set(remediation.build_checks()),
        )


class RemediationValidationTests(unittest.TestCase):

    def test_valid_remediation_generates_closure_evidence(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            output = (
                Path(directory)
                / "remediation-validation.json"
            )

            results = remediation.validate_remediation(
                "data/raw/mobile-security-findings.json",
                output,
            )

            self.assertEqual(len(results), 11)
            self.assertTrue(output.exists())

            self.assertTrue(
                all(
                    result["validation_status"]
                    == "Passed"
                    for result in results
                )
            )

            self.assertTrue(
                all(
                    result["disposition"] == "Closed"
                    for result in results
                )
            )

    def test_reintroduced_backup_weakness_is_rejected(
        self,
    ):
        secure_manifest = (
            remediation.REMEDIATED_MANIFEST
            .read_text(encoding="utf-8")
        )

        weakened_manifest = secure_manifest.replace(
            'android:allowBackup="false"',
            'android:allowBackup="true"',
        )

        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            manifest_path = (
                directory_path / "AndroidManifest.xml"
            )
            output_path = (
                directory_path / "validation.json"
            )

            manifest_path.write_text(
                weakened_manifest,
                encoding="utf-8",
            )

            with patch.object(
                remediation,
                "REMEDIATED_MANIFEST",
                manifest_path,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "MS-009",
                ):
                    remediation.validate_remediation(
                        (
                            "data/raw/"
                            "mobile-security-findings.json"
                        ),
                        output_path,
                    )

    def test_reintroduced_http_endpoint_is_rejected(
        self,
    ):
        secure_activity = (
            remediation.REMEDIATED_ACTIVITY
            .read_text(encoding="utf-8")
        )

        weakened_activity = secure_activity.replace(
            "https://api.mobileshield.test",
            "http://api.mobileshield.test",
        )

        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            activity_path = (
                directory_path / "MainActivity.kt"
            )
            output_path = (
                directory_path / "validation.json"
            )

            activity_path.write_text(
                weakened_activity,
                encoding="utf-8",
            )

            with patch.object(
                remediation,
                "REMEDIATED_ACTIVITY",
                activity_path,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "MS-004",
                ):
                    remediation.validate_remediation(
                        (
                            "data/raw/"
                            "mobile-security-findings.json"
                        ),
                        output_path,
                    )

    def test_missing_required_source_file_is_rejected(
        self,
    ):
        missing_path = Path(
            "does-not-exist/MainActivity.kt"
        )

        with patch.object(
            remediation,
            "REMEDIATED_ACTIVITY",
            missing_path,
        ):
            with self.assertRaisesRegex(
                FileNotFoundError,
                "Required file not found",
            ):
                remediation.build_checks()


if __name__ == "__main__":
    unittest.main()