# LinkedIn post — Friday ship for raksha-iac (Week 4 / Anchor)

## Primary version (~1800 chars, recommended)

I ran `tfsec` and `Checkov` on a fintech client's Terraform last quarter. Good tools. Both missed every single control that mattered for the RBI audit they were preparing for.

This week's ship is the answer to that gap: **raksha-iac** — an open-source Terraform security scanner with first-class rules for **DPDPA**, **RBI Cyber Security Framework**, and **CERT-In Directive 2022**.

What you get:
→ Three rule packs — `generic` (12 cloud best-practices), `dpdpa` (7 checks from the 2023 Act), `rbi` (5 checks from RBI + CERT-In)
→ Every finding carries a regulatory citation, not just a description (DPDPA §8(5), RBI IT Outsourcing Guidelines, etc.) — built into the `Rule` model
→ Optional AI remediation: pass `--remediate` and Claude (or OpenAI) writes the natural-language explanation plus a corrected Terraform snippet
→ SARIF + HTML + JSON output; non-zero exit code on HIGH/CRITICAL findings → drop straight into CI

Two design decisions I was deliberate about:

1. **Deterministic scanner first, LLM strictly opt-in.** The scanner makes zero network calls. The LLM is a productivity layer for the *fix* step, not the *find* step. Regulatory artefacts must be reproducible — same input, same SARIF, same day. LLM nondeterminism breaks that. The split keeps the system-of-record clean.

2. **Citations as first-class metadata.** Each rule's `reference` field is required, not a comment. When an auditor asks "*why* is this a finding," your report already answers. That's the difference between a finding compliance teams can use and one they have to translate.

It's not a replacement for `tfsec` — that tool has years of community rules. It's a *complement* that fills the India-specific gap. Run both. Fail the build on either.

The deeper write-up (design decisions, full rule coverage, what's next): github.com/uchandrachur/raksha-iac/blob/main/docs/anchor-article.md

Repo: github.com/uchandrachur/raksha-iac

This is week 4 of a 12-week series — small AI-augmented network security tools, shipped every Friday. Week 2 was `fgt-explain`; week 3 was `tf-net-summary`. Week 5 is in progress.

*Raksha* (रक्षा) means "protection" in Sanskrit.

Which Indian regulatory framework should be the next rule pack — IRDAI, MeitY, or SEBI? I'd love to know which gap is most painful. Comments are open.

#DPDPA #RBI #CloudSecurity #Terraform #DevSecOps #ComplianceAsCode #InfoSec #IndiaCyber #LLM #Claude

---

## Short version (~700 chars)

Week 4 of the AI-in-network-security build series:

**raksha-iac** — open-source Terraform scanner with first-class rules for **DPDPA**, **RBI**, and **CERT-In**. Every finding carries a §reference, not just a description. AI-augmented remediation is opt-in (deterministic scanner first, LLM second). SARIF + HTML output; CI-ready.

Not a replacement for `tfsec` — a complement that fills the India compliance gap.

Deep write-up: github.com/uchandrachur/raksha-iac/blob/main/docs/anchor-article.md
Repo: github.com/uchandrachur/raksha-iac

Which framework should be the next pack — IRDAI, MeitY, or SEBI?

#DPDPA #RBI #CloudSecurity #Terraform #DevSecOps

---

## Substack version (~2000 chars)

**Compliance-as-code, but make it Indian**

I've been doing cloud security for seventeen years. Most of that time, the playbook has been imported wholesale from US frameworks — SOC 2, HIPAA, NIST, FedRAMP. Even when we were securing rupee-denominated workloads for Indian regulators, the tooling spoke English-of-California.

That's mostly fine for generic controls. Encryption is encryption. A public S3 bucket is a public S3 bucket. But it falls apart the moment you need to demonstrate compliance with something India-specific — DPDPA §8(5), RBI's data residency expectation, the CERT-In Directive's 180-day log retention. None of the popular open-source IaC scanners know those rules exist.

So I wrote one that does.

**`raksha-iac`** is a Terraform security scanner with three rule packs:

- `generic` — 12 cloud security best-practices (same surface area as `tfsec` for the basics)
- `dpdpa` — 7 checks derived from the Digital Personal Data Protection Act, 2023
- `rbi` — 5 checks from the RBI Cyber Security Framework and the CERT-In Directive 2022

Every finding carries a regulatory citation as a first-class field — not a comment. When the auditor asks why, the citation is right there:

> ✗ HIGH  DPDPA-002  Personal data bucket missing encryption-at-rest
>         DPDPA §8(5): encryption is a "reasonable security safeguard"
>         for personal data fiduciaries.

I want to be careful about two things, and they're both design decisions worth talking about.

**The scanner is deterministic. The LLM is opt-in.** Regulatory artefacts must be reproducible. The same Terraform on the same day must produce the same SARIF report. LLM nondeterminism breaks that property. So the scanner does zero network calls — it parses HCL2, evaluates Python predicates, writes a report. If you pass `--remediate`, Claude (or OpenAI) generates the natural-language explanation and the corrected snippet. Find first, fix second; deterministic first, LLM second.

**`raksha-iac` is not a replacement for `tfsec` or `Checkov`.** Those tools have years of community-built rules. `raksha-iac` is a complement that fills the India-specific gap. Run both in your pipeline. Fail the build on either.

The full write-up — including the rule coverage tables, the architecture, the three design decisions in detail, and the roadmap — is in the repo: [github.com/uchandrachur/raksha-iac/blob/main/docs/anchor-article.md](https://github.com/uchandrachur/raksha-iac/blob/main/docs/anchor-article.md).

*Raksha* (रक्षा) means "protection" in Sanskrit. The name was the easy part.

If you've been on the compliance side of an Indian BFSI, healthcare, or regulated SaaS team, I'd like to ask one question: which framework should be the next rule pack — IRDAI for insurers, MeitY for intermediaries, or SEBI for capital markets? I want to start with whichever has the most acute gap.

Hit reply, or drop a note on the LinkedIn version of this post. Both work.

— Uma

---

## Posting tips for this Friday

1. **Screenshot the colored CLI output.** The DPDPA-002 + RBI-001 + GEN-001 mix in a single scan is the visual hook — it shows the multi-pack story in one frame.
2. **First two lines hook.** "I ran tfsec and Checkov on a fintech client's Terraform last quarter. Good tools. Both missed every single control that mattered for the RBI audit." — keep it as-is. The "good tools" beat is what stops the scroll.
3. **Drop the repo link in the body** (matches the prior `fgt-explain` post; LinkedIn de-prioritises external links *less* when the post is substantive — this one is). Pin a follow-up comment with the anchor article URL.
4. **Engage in the first hour.** Reply to every comment. For this post specifically, when someone names a framework (IRDAI / MeitY / SEBI), thank them and ask a follow-up — that's the signal you'll use to pick the next rule pack.
5. **Tag selectively.** Only DPOs / compliance leads who would genuinely engage. Avoid spray-tagging.
6. **Time it for the India audience.** Friday 9–10 AM IST. The compliance angle resonates strongest with India-timezone professionals during work hours.
7. **Cross-post a 2-line follow-up on Monday.** "Thanks everyone — `raksha-iac` crossed N stars over the weekend. Most-requested next pack: X. Building it this week." Compounds engagement and signals momentum.
8. **For the recruiter/hiring-manager audience specifically:** the substantive bits to highlight in the first half — "every finding carries a regulatory citation, not just a description" and "deterministic scanner first, LLM strictly opt-in." Both show product judgement, not just feature checklists.
