# Security automation

Runs four command-line tools against one directory and combines their findings into a single pass/fail report. The wrapper uses only the Python standard library (Python 3.9+).

| Scan | Tool | Coverage |
| --- | --- | --- |
| SAST | Semgrep | Source code patterns |
| Dependencies | Trivy | Vulnerabilities in supported dependency manifests and lockfiles |
| Secrets | Gitleaks | Files in the target directory (not Git history) |
| IaC | Checkov | Supported infrastructure configuration files |

Install `semgrep`, `trivy`, `gitleaks`, and `checkov` using their official instructions, and put their executables on `PATH`. For Python environments, for example, `python -m pip install semgrep checkov`; install the other two binaries separately. Trivy may download a vulnerability database and Semgrep `--config auto` may fetch rules, so network access may be needed on a first run. For offline SAST, point `--semgrep-config` at a local rules file. Include your project's lockfiles for useful dependency coverage.

## Usage

```bash
cd security-automation
chmod +x security-scan.py
./security-scan.py --path ./app --format json
./security-scan.py --path ../my-project --format text --fail-on high
./security-scan.py --path ../my-project --format json --timeout 600 --semgrep-config ./rules.yml
```

Use an existing project directory for `--path`. The JSON report contains `decision`, `summary`, `tools`, and normalized `findings` with category, severity, rule, file, and line. The `--fail-on` threshold defaults to `medium`; Gitleaks findings are `critical`. Checkov community findings may have no severity, in which case this wrapper marks them `medium` (the same default is used for other unknown severities). Lower severity findings still appear in the report.

Exit codes: `0` pass, `1` one or more findings meet the threshold, `2` incomplete scan (tool missing, scanner error, timeout, or unreadable output). Incomplete scans always take priority over findings, so CI cannot silently pass when coverage is missing. The output intentionally excludes secret matches and raw scanner stderr. Treat the report as sensitive because file names and other finding details may reveal information.

## Tests and examples

The tests simulate scanner output; they do not need the four tools installed:

```bash
python -m unittest discover -s tests -v
```

The three cases cover a clean scan, a finding that fails the gate (including secret redaction), and a missing scanner that makes the scan incomplete. To try a real project, install all four tools and run the usage command above. A directory without any matching files or manifests can pass with little coverage; review the scanner output and project contents.

CLI references: [Semgrep](https://semgrep.dev/docs/cli-reference/), [Trivy filesystem](https://www.trivy.dev/docs/latest/guide/references/configuration/cli/trivy_filesystem/), [Gitleaks](https://github.com/gitleaks/gitleaks), [Checkov](https://www.checkov.io/2.Basics/CLI%20Command%20Reference.html).
