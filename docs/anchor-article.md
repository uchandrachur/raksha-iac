# Compliance-as-code for India: why I built raksha-iac

> Open-source IaC scanners are excellent. They're also written almost entirely from a US/EU compliance perspective. For Indian BFSI, healthcare, and regulated SaaS, that leaves a gap. `raksha-iac` is my attempt to fill it.

---

## The gap that started this

Last quarter I was helping a fintech team get their Terraform reviewed before an RBI audit. We ran `tfsec` and `Checkov` — both flagged the obvious things: public S3 buckets, wildcard IAM, missing encryption flags. Good catches. But neither tool said a word about:

- Whether the resources were deployed inside India (RBI IT Outsourcing Guidelines)
- Whether personal-data resources carried a `data_classification` tag (DPDPA §8(8))
- Whether the encryption strength met the RBI Cyber Security Framework minimum
- Whether audit logs would be retained the full 7 years RBI expects for financial workloads
- Whether the architecture had a cross-border data transfer path that DPDPA §16 flags

None of those are obscure controls. They're table-stakes for any Indian regulated entity. They just aren't in the rule libraries of tools built for SOC 2 and HIPAA.

So I wrote one.

## What raksha-iac does

`raksha-iac` is a Python CLI that scans Terraform code with three independent rule packs:

- **`generic`** — 12 cloud security best-practices that apply everywhere
- **`dpdpa`** — 7 checks derived from India's Digital Personal Data Protection Act, 2023
- **`rbi`** — 5 checks from the RBI Cyber Security Framework and CERT-In Directive 2022

Every finding carries a regulatory citation, not just a description. That matters: when an auditor asks "*why* is this a finding," you have the answer in the same line of output.

```
✗ HIGH      DPDPA-002  Personal data bucket missing encryption-at-rest
            examples/bad.tf:4   resource "aws_s3_bucket.user_data"
            DPDPA §8(5): encryption is a "reasonable security safeguard"
            for personal data fiduciaries.
```

That citation isn't a comment — it's a first-class field on the `Finding` model. Same for RBI rules:

```
✗ HIGH      RBI-001    Resources deployed in non-Indian regions
                       RBI IT Outsourcing Guidelines: data localisation
                       requirement for regulated entities.
```

## Three design decisions I want to call out

### 1. Regulatory citations as first-class metadata

Every `Rule` has a `reference` field. It's required, not optional. The decision came from a practical observation: in regulated environments, the *citation* is the most useful piece of information a finding can carry, because that's what compliance teams and external auditors actually consume. Severity tells engineers what to fix; the citation tells compliance teams *why it appears in their report*.

### 2. AI remediation is opt-in, not default

The scanner itself does zero network calls. It parses HCL2, evaluates Python predicates against a `Resource` model, and writes a report. The LLM only enters the picture when you pass `--remediate`, which sends each finding (and only the finding — never the surrounding code) to Claude or OpenAI for a natural-language explanation and a corrected Terraform snippet.

Two reasons for that split:

- **Regulatory artefacts must be deterministic.** The same code on the same day must produce the same SARIF report. LLM nondeterminism breaks that property. The deterministic scanner is the system of record; the LLM is a productivity layer on top.
- **Most teams I've worked with cannot send infrastructure code to a third party without a procurement review.** Defaulting to "local only" is the right behaviour. Opt-in for LLM remediation respects that.

### 3. Rule packs are independent and pluggable

`generic`, `dpdpa`, and `rbi` are separate packs you can enable individually. A non-regulated team can run `--rules generic` and get a tool that looks like `tfsec`. A BFSI team can run `--rules generic,dpdpa,rbi` and get the full picture. Adding a new rule is a single Python class:

```python
class DpdpaConsentTagMissing(Rule):
    id = "DPDPA-001"
    severity = Severity.HIGH
    description = "Personal data resource missing consent tag"
    reference = "DPDPA §6, §7 (Notice & Consent)"
    resource_types = ["aws_s3_bucket", "aws_rds_db_instance", "aws_dynamodb_table"]

    def evaluate(self, r: Resource) -> bool:
        tags = r.config.get("tags", {})
        return tags.get("data_classification") == "personal" \
               and "consent_basis" not in tags
```

That's it. Drop the file in `raksha/rules/dpdpa.py`, register it in `__init__.py`, done.

## Rule coverage at a glance

**DPDPA pack (7 rules)** — Notice & Consent (§6, §7), encryption-at-rest (§8(5)), cross-border transfer (§16), erasure (§8(7)), classification tagging (§8(8)), audit logging (§8(8) + CERT-In), Significant Data Fiduciary controls (§10).

**RBI / CERT-In pack (5 rules)** — Indian-region residency (RBI IT Outsourcing Guidelines), encryption strength (RBI Cyber Security Framework: AES-256, TLS 1.2+), 7-year audit retention (RBI), 180-day log retention (CERT-In 2022), NTP synchronisation to NIC servers (CERT-In 2022).

**Generic pack (12 rules)** — S3 public read, wildcard IAM, security groups open to 0.0.0.0/0 on sensitive ports, missing encryption flags, unencrypted snapshots, RDS public accessibility, KMS rotation disabled, IMDSv2 not enforced, ELB without TLS, CloudTrail not enabled, root account API keys, missing tags.

## Where this fits — and what it deliberately is not

|                                  | tfsec | Checkov | terrascan | **raksha-iac** |
|----------------------------------|:-----:|:-------:|:---------:|:--------------:|
| Generic cloud rules              |   ✅  |    ✅   |     ✅    |       ✅       |
| AWS / Azure / GCP                |   ✅  |    ✅   |     ✅    |       ✅       |
| **DPDPA-specific rules**         |   ❌  |    ❌   |     ❌    |       ✅       |
| **RBI / CERT-In rules**          |   ❌  |    ❌   |     ❌    |       ✅       |
| AI-augmented remediation         |   ❌  |    ❌   |     ❌    |       ✅       |

`raksha-iac` is not a replacement for `tfsec` or `Checkov`. Those tools have years of community-built rules and far broader cloud coverage. `raksha-iac` is a *complement* — it sits next to them in your CI pipeline and adds the India-specific layer they don't cover. Run it after them, fail the build on its findings too.

## What I'd build next

The roadmap I'm thinking about, in order:

- OPA / Rego export so teams using OPA-native pipelines can adopt the rules without changing toolchains
- CloudFormation and Pulumi parser support (the rule layer is parser-agnostic — only the front-end changes)
- A VS Code extension that lights up DPDPA / RBI findings in-editor
- Auto-fix mode that writes the remediation back to the `.tf` file under a `--fix` flag, gated by a confirmation prompt

**The thing I'd most like feedback on:** which Indian regulatory framework should be the *next* rule pack? IRDAI for insurers, MeitY guidelines for intermediaries, SEBI for capital markets — these all have IaC-checkable controls. I don't have the bandwidth to do all three; I'd like to start with whichever has the strongest demand.

If you've worked on the compliance side of any of those, I'd love to hear which gap is most painful.

---

*A note: I'm not a lawyer. The DPDPA and RBI rule sets are derived from publicly available regulatory text and represent my working interpretation. For production use, have a qualified DPO and corporate counsel review them. The rules are open source precisely so that legal review is possible — you can read every check, line by line.*

---

**About this series.** This is week 4 of a 12-week build series — one small AI-augmented network security tool shipped each Friday. Past weeks: [`fgt-explain`](https://github.com/uchandrachur/fgt-explain) (FortiGate policy reviewer, week 2), `tf-net-summary` (Terraform architecture explainer, week 3). Repo: [github.com/uchandrachur/raksha-iac](https://github.com/uchandrachur/raksha-iac).

*Uma Dayal Chandrachur — Senior Cloud Security Architect (17+ years), PG Diploma in Cyber Law & Forensics, NLSIU Bengaluru. [LinkedIn](https://www.linkedin.com/in/umadayal).*
