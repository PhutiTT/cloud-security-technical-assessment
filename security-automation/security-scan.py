#!/usr/bin/env python3
"""Run four security scanners and combine their findings into one report."""

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

LEVELS = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def severity(value, default="medium"):
    name = str(value or "").lower()
    return name if name in LEVELS else default


def finding(tool, category, rule, message, file, line=None, level="medium"):
    return {"tool": tool, "category": category, "severity": severity(level),
            "rule_id": str(rule or "unknown"), "message": str(message or "Finding"),
            "file": str(file or ""), "line": line if isinstance(line, int) else None}


def parse_semgrep(data):
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise ValueError("invalid Semgrep report")
    if data.get("errors"):
        raise ValueError("Semgrep reported scan errors")
    mapping = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    return [finding("semgrep", "sast", item.get("check_id"),
                    item.get("extra", {}).get("message"), item.get("path"),
                    item.get("start", {}).get("line"),
                    mapping.get(str(item.get("extra", {}).get("severity", "")).upper(), "medium"))
            for item in data["results"]]


def parse_trivy(data):
    if not isinstance(data, dict) or "Results" not in data or not isinstance(data["Results"], (list, type(None))):
        raise ValueError("invalid Trivy report")
    return [finding("trivy", "dependency", v.get("VulnerabilityID"),
                    f"{v.get('PkgName', 'package')} {v.get('InstalledVersion', '')}: {v.get('Title') or v.get('VulnerabilityID', 'vulnerability')}",
                    result.get("Target"), level=v.get("Severity"))
            for result in (data["Results"] or []) for v in (result.get("Vulnerabilities") or [])]


def parse_gitleaks(data):
    if not isinstance(data, list):
        raise ValueError("invalid Gitleaks report")
    # Never put a matched secret, fingerprint, or surrounding code in the unified report.
    return [finding("gitleaks", "secrets", item.get("RuleID"),
                    item.get("Description") or "Potential secret", item.get("File"),
                    item.get("StartLine"), "critical") for item in data]


def parse_checkov(data):
    reports = data if isinstance(data, list) else [data]
    if not reports or any(not isinstance(r, dict) or not isinstance(r.get("results"), dict)
                          or not isinstance(r["results"].get("failed_checks"), list) for r in reports):
        raise ValueError("invalid Checkov report")
    return [finding("checkov", "iac", item.get("check_id"), item.get("check_name"),
                    item.get("file_path"),
                    (item.get("file_line_range") or [None])[0],
                    item.get("severity"))
            for report in reports for item in report["results"]["failed_checks"]]


def run_scanner(tool, command, parser, report_file=None, allowed=(0,), timeout=300):
    if not shutil.which(command[0]):
        return {"status": "error", "error": f"{command[0]} is not installed or not on PATH", "findings": []}
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        if proc.returncode not in allowed:
            raise ValueError(f"scanner exited with code {proc.returncode}")
        raw = (Path(report_file).read_text(encoding="utf-8") if Path(report_file).exists() else "") if report_file else proc.stdout
        # Gitleaks may leave an empty or absent report on a clean scan.
        if tool == "gitleaks" and proc.returncode == 0 and not raw.strip():
            raw = "[]"
        items = parser(json.loads(raw))
        return {"status": "ok", "findings": items}
    except (subprocess.TimeoutExpired, OSError, ValueError, json.JSONDecodeError) as exc:
        error = "timed out" if isinstance(exc, subprocess.TimeoutExpired) else (
            str(exc) if isinstance(exc, ValueError) else "could not read scanner report")
        return {"status": "error", "error": error, "findings": []}


def scan(path, threshold="medium", timeout=300, semgrep_config="auto"):
    target = str(Path(path).resolve())
    with tempfile.TemporaryDirectory(prefix="security-scan-") as temp:
        leak_report = str(Path(temp) / "gitleaks.json")
        specs = [
            ("semgrep", ["semgrep", "scan", "--config", semgrep_config, "--json", target], parse_semgrep, None, (0,)),
            ("trivy", ["trivy", "fs", "--scanners", "vuln", "--format", "json", "--exit-code", "0", target], parse_trivy, None, (0,)),
            ("gitleaks", ["gitleaks", "dir", target, "--report-format", "json", "--report-path", leak_report, "--redact"], parse_gitleaks, leak_report, (0, 1)),
            ("checkov", ["checkov", "-d", target, "-o", "json", "--soft-fail"], parse_checkov, None, (0,)),
        ]
        tools = {name: run_scanner(name, command, parser, report, allowed, timeout)
                 for name, command, parser, report, allowed in specs}
    findings = [item for result in tools.values() for item in result["findings"]]
    errors = [name for name, result in tools.items() if result["status"] == "error"]
    blocking = sum(LEVELS[item["severity"]] >= LEVELS[threshold] for item in findings)
    decision = "error" if errors else "fail" if blocking else "pass"
    return {"path": target, "decision": decision, "threshold": threshold,
            "summary": {"findings": len(findings), "blocking": blocking, "scanner_errors": len(errors)},
            "tools": {name: {key: value for key, value in result.items() if key != "findings"}
                      for name, result in tools.items()}, "findings": findings}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--path", required=True, help="directory to scan")
    ap.add_argument("--format", choices=("json", "text"), default="text")
    ap.add_argument("--fail-on", choices=tuple(LEVELS), default="medium")
    ap.add_argument("--timeout", type=int, default=300, help="seconds per scanner")
    ap.add_argument("--semgrep-config", default="auto", help="Semgrep ruleset or local rules path")
    args = ap.parse_args(argv)
    if not Path(args.path).is_dir() or args.timeout < 1:
        ap.error("--path must be a directory and --timeout must be positive")
    report = scan(args.path, args.fail_on, args.timeout, args.semgrep_config)
    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print(f"{report['decision'].upper()}: {report['summary']['findings']} findings; "
              f"{report['summary']['blocking']} blocking; {report['summary']['scanner_errors']} scanner errors")
        for name, state in report["tools"].items():
            if state["status"] == "error":
                print(f"  {name}: ERROR ({state['error']})")
        for item in report["findings"]:
            print(f"  {item['severity'].upper()} {item['tool']} {item['rule_id']} "
                  f"{item['file']}:{item['line'] or '-'} {item['message']}")
    return {"pass": 0, "fail": 1, "error": 2}[report["decision"]]


if __name__ == "__main__":
    sys.exit(main())
