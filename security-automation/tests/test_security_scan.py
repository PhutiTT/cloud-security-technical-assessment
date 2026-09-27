import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "security-scan.py"
spec = importlib.util.spec_from_file_location("security_scan", SCRIPT)
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


class ScanTests(unittest.TestCase):
    def test_clean_scan_passes(self):
        with patch.object(scanner, "run_scanner", return_value={"status": "ok", "findings": []}):
            report = scanner.scan(".")
        self.assertEqual(report["decision"], "pass")
        self.assertEqual(report["summary"], {"findings": 0, "blocking": 0, "scanner_errors": 0})

    def test_finding_fails_and_secret_is_not_exposed(self):
        leak = scanner.parse_gitleaks([{"RuleID": "generic-api-key", "Description": "Key found",
                                        "File": "config.txt", "StartLine": 3,
                                        "Secret": "DONT_PRINT_ME", "Match": "DONT_PRINT_ME"}])
        with patch.object(scanner, "run_scanner", side_effect=[
                {"status": "ok", "findings": []}, {"status": "ok", "findings": []},
                {"status": "ok", "findings": leak}, {"status": "ok", "findings": []}]):
            report = scanner.scan(".")
        self.assertEqual(report["decision"], "fail")
        self.assertEqual(report["summary"]["blocking"], 1)
        self.assertNotIn("DONT_PRINT_ME", json.dumps(report))

    def test_missing_tool_returns_error_exit_code_and_valid_json(self):
        with tempfile.TemporaryDirectory() as target, patch.object(scanner.shutil, "which", return_value=None):
            output = io.StringIO()
            with redirect_stdout(output):
                code = scanner.main(["--path", target, "--format", "json"])
        report = json.loads(output.getvalue())
        self.assertEqual(code, 2)
        self.assertEqual(report["decision"], "error")
        self.assertEqual(report["summary"]["scanner_errors"], 4)


if __name__ == "__main__":
    unittest.main()
