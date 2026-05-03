# raksha-iac

> Terraform security scanner with first-class support for **India-specific compliance** (DPDPA, RBI Guidelines) and **AI-augmented remediation**.

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-active-brightgreen.svg)](#)

## Why this exists

Existing IaC scanners (`tfsec`, `Checkov`, `terrascan`) are excellent at catching generic cloud misconfigurations but are written almost entirely from a US/EU compliance perspective. For Indian enterprises — especially BFSI, healthcare, and SaaS companies serving Indian customers — the relevant frameworks are different:

- **Digital Personal Data Protection Act, 2023 (DPDPA)** — India's privacy law, in force with rules notified through 2025–2026.
- **RBI Guidelines** — data residency, encryption standards, audit log retention, and access control requirements specific to regulated financial entities.
- **CERT-In Directive (April 2022)** — incident reporting, log retention (180 days minimum), and timestamping rules.

`raksha-iac` codifies these requirements as Terraform-scanning rules so that compliance is enforceable at the IaC layer, not just on paper. *Raksha* (रक्षा) means "protection" in Sanskrit.

---

## Features

- **Multi-cloud Terraform scanning** — AWS, Azure, GCP resource coverage.
- **Three rule sets bundled:**
  - `generic` — 12 cloud security best-practices (S3 public access, missing encryption, wildcard IAM, etc.)
  - `dpdpa` — 7 DPDPA compliance checks (PII tagging, encryption-at-rest for personal data, cross-border transfer guards, audit logging).
  - `rbi` — 5 RBI/CERT-In checks (Indian region residency, RBI-grade encryption, 7-year audit retention).
- **AI-augmented remediation** — every finding can be passed to an LLM (Claude or OpenAI) to generate a natural-language explanation plus a corrected Terraform snippet.
- **CI/CD friendly** — JSON, SARIF (GitHub Code Scanning), and HTML report outputs. Non-zero exit code on policy violation.
- **Pluggable rule engine** — add a new rule with a single Python class.
- **Zero network calls by default** — scanning is purely local; LLM remediation is opt-in.

---

## Quick start

```bash
# Install
pip install -e .

# Scan the example
raksha scan examples/bad.tf --rules generic,dpdpa --format html --out report.html

# Scan with AI remediation (set ANTHROPIC_API_KEY first)
raksha scan examples/bad.tf --rules dpdpa --remediate

# CI/CD usage — fails the build on HIGH/CRITICAL findings
raksha scan ./infra --severity-threshold HIGH --format sarif --out results.sarif
```

### Sample output

```
$ raksha scan examples/bad.tf --rules generic,dpdpa

╔═════════════════════════════════════════════════════════════════════╗
║  raksha-iac · scan complete                                          ║
║  rules: generic, dpdpa  ·  files: 1  ·  resources: 4                 ║
╚═════════════════════════════════════════════════════════════════════╝

✗ CRITICAL  GEN-001  S3 bucket allows public read
            examples/bad.tf:4   resource "aws_s3_bucket.user_data"

✗ HIGH      DPDPA-002  Personal data bucket missing encryption-at-rest
            examples/bad.tf:4   resource "aws_s3_bucket.user_data"
            DPDPA §8(5): encryption is a "reasonable security safeguard"
            for personal data fiduciaries.

✗ HIGH      DPDPA-005  Personal data resource missing classification tag
            examples/bad.tf:4   resource "aws_s3_bucket.user_data"
            Add tag "data_classification" = "personal" | "sensitive_personal"

✗ MEDIUM    GEN-005  Security group allows 0.0.0.0/0 on SSH (port 22)
            examples/bad.tf:38  resource "aws_security_group.public"

Summary:  4 findings   1 critical · 2 high · 1 medium
Exit code: 1
```

---

## Architecture

```
┌─────────────┐     ┌──────────┐     ┌──────────────┐     ┌─────────┐
│ Terraform   │ ──> │  Parser  │ ──> │ Rule Engine  │ ──> │ Reporter│
│  *.tf files │     │ (HCL2)   │     │              │     │         │
└─────────────┘     └──────────┘     └──────┬───────┘     └─────────┘
                                            │
                                     ┌──────┴──────┐
                                     │             │
                                ┌────▼────┐   ┌────▼────┐
                                │ generic │   │ dpdpa / │
                                │  rules  │   │  rbi    │
                                └─────────┘   └────┬────┘
                                                   │
                                            ┌──────▼──────┐
                                            │ LLM remedia.│
                                            │ (optional)  │
                                            └─────────────┘
```

Each rule is a single Python class subclassing `Rule`:

```python
class S3PublicAccess(Rule):
    id = "GEN-001"
    severity = Severity.CRITICAL
    description = "S3 bucket allows public read"
    resource_types = ["aws_s3_bucket_public_access_block"]

    def evaluate(self, resource: Resource) -> bool:
        cfg = resource.config
        return any([
            cfg.get("block_public_acls") is False,
            cfg.get("block_public_policy") is False,
            cfg.get("ignore_public_acls") is False,
            cfg.get("restrict_public_buckets") is False,
        ])
```

Adding a new rule = drop a file in `raksha/rules/` and import it in the package init.

---

## DPDPA Rule Coverage

| ID | Check | DPDPA Reference |
|---|---|---|
| DPDPA-001 | Personal data resource has consent tag | §6, §7 (Notice & Consent) |
| DPDPA-002 | Encryption-at-rest enabled for personal data resources | §8(5) (Reasonable security safeguards) |
| DPDPA-003 | Cross-border transfer to non-notified country | §16 (Transfer of personal data outside India) |
| DPDPA-004 | Backup retention not aligned with deletion obligation | §8(7) (Erasure) |
| DPDPA-005 | Personal data resource missing classification tag | §8(8) (Reasonable security safeguards) |
| DPDPA-006 | Audit logging not enabled for personal data access | §8(8), CERT-In Directive |
| DPDPA-007 | Significant Data Fiduciary controls (DPIA tag) | §10 (Significant Data Fiduciary) |

> **Disclaimer:** This tool is a working interpretation of public law. It is not legal advice and not a substitute for a Data Protection Officer review.

---

## RBI / CERT-In Rule Coverage

| ID | Check | Reference |
|---|---|---|
| RBI-001 | Resources deployed in non-Indian regions for regulated entities | RBI IT Outsourcing Guidelines |
| RBI-002 | Encryption strength below RBI minimum (AES-256, TLS 1.2+) | RBI Cyber Security Framework |
| RBI-003 | Audit log retention < 7 years for financial workloads | RBI guidelines |
| CERTIN-001 | Log retention < 180 days | CERT-In Directive 2022 |
| CERTIN-002 | NTP synchronization to non-NIC servers | CERT-In Directive 2022 |

---

## Comparison with existing tools

|                                  | tfsec | Checkov | terrascan | **raksha-iac** |
|----------------------------------|:-----:|:-------:|:---------:|:--------------:|
| Generic cloud rules              |   ✅  |    ✅   |     ✅    |       ✅       |
| AWS / Azure / GCP                |   ✅  |    ✅   |     ✅    |       ✅       |
| **DPDPA-specific rules**         |   ❌  |    ❌   |     ❌    |       ✅       |
| **RBI / CERT-In rules**          |   ❌  |    ❌   |     ❌    |       ✅       |
| AI-augmented remediation         |   ❌  |    ❌   |     ❌    |       ✅       |
| SARIF output                     |   ✅  |    ✅   |     ✅    |       ✅       |

`raksha-iac` is not a replacement for `tfsec` or `Checkov` — those tools have years of community-built rules. It is a **complement** that fills the India-specific gap, and a demonstration of how compliance-as-code can be tailored to local regulation.

---

## Roadmap

- [x] Generic cloud rules (12 rules across AWS / Azure / GCP)
- [x] DPDPA rule pack (7 rules)
- [x] RBI / CERT-In rule pack (5 rules)
- [x] AI remediation via Anthropic / OpenAI
- [x] HTML and SARIF reporters
- [ ] OPA / Rego export for OPA-native pipelines
- [ ] CloudFormation and Pulumi support
- [ ] VS Code extension for in-editor scanning
- [ ] Auto-fix mode (writes remediation back to .tf file)
- [ ] Web UI for non-technical compliance reviewers

---

## Project status & disclaimers

This project is a **portfolio / proof-of-concept** built to demonstrate:
- Modern Python (3.11+, typed, pydantic-based)
- Terraform / IaC fluency
- Multi-cloud security architecture knowledge
- Indian regulatory framework expertise (DPDPA, RBI, CERT-In)
- LLM integration patterns

The DPDPA and RBI rule sets are derived from publicly available regulatory text and represent the author's interpretation. Production use should be reviewed by a qualified Data Protection Officer and corporate counsel.

---

## Author

**Uma Dayal Chandrachur**
Senior Cloud Security Architect · 17+ years
PG Diploma in Cyber Law & Forensics, NLSIU Bengaluru
[LinkedIn](https://www.linkedin.com/in/umadayal) · umadayal@hotmail.com

## License

MIT — see [LICENSE](LICENSE) for details.
