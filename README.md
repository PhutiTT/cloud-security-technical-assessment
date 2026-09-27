# Cloud Security Technical Assessment

This repository answers all three questions in the supplied assessment:

| Question | Folder | Contents |
| --- | --- | --- |
| 1. Security automation | `security-automation/` | Python scanner, usage guide, three tests |
| 2. Risk review | `risk-review/` | SSM automation and RDS access policy reviews against Annexures A-D |
| 3. Required SCP | `required-scp/` | AWS Organizations region SCP and rollout guidance |

To run the automated tests without installing the scanners:

```bash
python3 -m unittest discover -s security-automation/tests -v
python3 -m json.tool required-scp/region-restriction.json > /dev/null
```

The security automation scanner itself requires Semgrep, Trivy, Gitleaks, and Checkov. See its folder README for setup and examples. The risk review is advisory; the SCP is an example to pilot, not a deployed control. No AWS account was accessed or changed.
