# Compliance & Cyber-Insurance Control Map

Maps restoregap evidence types to the framework controls and underwriting
questions that drive purchases. Every control ID below was verified against
the cited source on **2026-07-16**; anything not verifiable from a primary
source in this pass is explicitly marked UNVERIFIED rather than guessed.
This file is the human-readable companion to `compliance/controls.yaml`
(consumed by `restoregap evidence --framework ...`).

## Where the money is (ranked for restoregap's ICP)

1. **Cyber-insurance underwriting** — every renewal, every year, for every
   company with a policy. Carrier applications ask directly for what
   restoregap proves: Coalition's Ransomware Supplemental asks *"Do you test
   the successful restoration and recovery of key server configurations and
   data from backups?"* alongside offline/segregated-backup questions.
   A signed, hash-bound restore-drill proof answers that question with
   evidence instead of a checkbox. This is the sharpest wedge: the buyer
   already has a deadline (renewal) and a price lever (premium/insurability).
2. **SOC 2 (Availability)** — deal-blocking for B2B SaaS. Auditors take
   exceptions for untested recovery; A1.3 explicitly requires tested recovery
   procedures. Evidence packets slot into the audit request list.
3. **ISO 27001:2022** — same buyer motion as SOC 2, international.
4. **NIST CSF 2.0 / 800-53 / CIS v8** — the vocabulary of security programs
   and government-adjacent buyers; free credibility to speak it in exports.
5. **HIPAA / DORA** — vertical wedges (healthcare; EU financial entities).
   DORA is notable because Article 12 makes backup+restoration testing a
   standalone legal obligation, not a best practice.

## Evidence types (restoregap vocabulary)

| id | evidence |
|---|---|
| `restore-drill` | Verified restore test, hash-bound + timestamped (optionally Ed25519-signed) |
| `backup-freshness` | Backup existence, age, and retention state |
| `offline-copy` | Independent/offline/immutable recovery copy outside the resource's own account/machine |
| `recovery-path` | Documented + tested alternate access and recovery runbooks |
| `gated-change` | Preflight decisions on risky changes, recorded in an append-only ledger |
| `drift-history` | Recovery-posture history, expiring exceptions, drift over time |

## Verified mappings

### Cyber-insurance underwriting (example: Coalition)
Source: Coalition Cyber application + Ransomware Supplemental Questionnaire
(broker-published copy: gunnmowery.com/wp-content/uploads/Coalition-Cyber-EO-with-Ransomware-Supplemental.pdf, retrieved 2026-07-16).
- "Do you test the successful restoration and recovery of key server
  configurations and data from backups?" → `restore-drill` (direct)
- Offline/segregated backup questions in the same supplemental → `offline-copy` (direct)
- Backup frequency/coverage questions → `backup-freshness` (direct)
- BC/DR documentation questions → `recovery-path` (direct)
Other carriers (Chubb, Travelers, At-Bay, Beazley) ask equivalent questions;
their questionnaire texts were NOT individually verified in this pass — cite
Coalition when naming a specific carrier question.

### SOC 2 — 2017 Trust Services Criteria (Availability)
Source: AICPA TSC as summarized by multiple audit-firm references
(soc2auditors.org, drata.com trust-services-criteria, retrieved 2026-07-16).
- **A1.2** — environmental protections, software, **data backup processes,
  and recovery infrastructure** are authorized, designed, developed,
  implemented, operated, maintained → `backup-freshness` (direct),
  `offline-copy` (supporting), `recovery-path` (supporting)
- **A1.3** — **recovery plan procedures are tested** → `restore-drill` (direct)
- **CC7.5** — activities to recover from identified security incidents →
  `recovery-path` (supporting), `drift-history` (supporting)
Note: quote criterion text from the AICPA TSC document itself before putting
it in customer-facing copy (audit-firm paraphrases verified here, not the
AICPA original).

### ISO/IEC 27001:2022 Annex A
Source: ISMS.online / iso27001.com control references + hightable.io
(retrieved 2026-07-16; the standard itself is paywalled — wording verified
via multiple independent implementation guides).
- **A.8.13 Information backup** — backups maintained and **regularly
  tested** → `restore-drill` (direct), `backup-freshness` (direct)
- **A.8.14 Redundancy of information processing facilities** →
  `offline-copy` (supporting), `recovery-path` (supporting)
- **A.5.30 ICT readiness for business continuity** → `recovery-path`
  (direct), `restore-drill` (supporting)

### NIST CSF 2.0
Source: NIST CSWP 29 (nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf) and
NIST CSF 2.0 Core document (retrieved 2026-07-16).
- **PR.DS-11** — "Backups of data are created, protected, maintained, and
  tested" → `restore-drill` (direct), `backup-freshness` (direct),
  `offline-copy` (direct)
- **RC.RP (Incident Recovery Plan Execution)**, incl. **RC.RP-01** ("the
  recovery portion of the incident response plan is executed") →
  `recovery-path` (direct), `restore-drill` (supporting)

### NIST SP 800-53 rev 5
Source: csf.tools/reference/nist-sp-800-53/r5/cp/ (retrieved 2026-07-16).
- **CP-9 System Backup** → `backup-freshness` (direct), `offline-copy` (supporting)
- **CP-10 System Recovery and Reconstitution** → `recovery-path` (direct)
- **CP-4 Contingency Plan Testing** → `restore-drill` (direct)

### CIS Controls v8 / v8.1 — Control 11: Data Recovery
Source: cas.docs.cisecurity.org Controls11 + csf.tools v8-1 csc-11
(retrieved 2026-07-16).
- **11.1** Establish and Maintain a Data Recovery Process → `recovery-path` (direct)
- **11.2** Perform Automated Backups → `backup-freshness` (direct)
- **11.3** Protect Recovery Data → `offline-copy` (supporting)
- **11.4** Establish and Maintain an **Isolated Instance of Recovery Data** → `offline-copy` (direct)
- **11.5** Test Data Recovery → `restore-drill` (direct)

### HIPAA Security Rule — 45 CFR §164.308(a)(7) Contingency Plan
Source: HHS Security Series #2, Administrative Safeguards
(hhs.gov/sites/default/files/ocr/privacy/hipaa/administrative/securityrule/adminsafeguards.pdf, retrieved 2026-07-16).
- **(ii)(A) Data Backup Plan (Required)** → `backup-freshness` (direct), `offline-copy` (supporting)
- **(ii)(B) Disaster Recovery Plan (Required)** → `recovery-path` (direct)
- **(ii)(D) Testing and Revision Procedures (Addressable)** → `restore-drill` (direct)

### DORA — Regulation (EU) 2022/2554
Source: digital-operational-resilience-act.com/Article_12.html (unofficial
consolidated text, retrieved 2026-07-16; cite the Official Journal text in
customer-facing material).
- **Article 12** — backup policies and procedures + **restoration and
  recovery procedures and methods**; backup systems that can be activated →
  `backup-freshness`, `restore-drill`, `recovery-path` (all direct)

## UNVERIFIED in this pass (do not cite until checked)

- **PCI DSS v4.0.x** — backup/recovery-adjacent requirement numbers were not
  confirmed against the v4 standard (v3.2.1-era references like 9.5.1 media
  backup do not carry over cleanly). Verify against the official PCI SSC
  document before mapping.
- **NYDFS 23 NYCRR 500** — §500.16 BCDR/incident response is the likely
  anchor post-2023 amendment; not verified.
- Specific Chubb/Travelers/At-Bay/Beazley questionnaire texts.

## Product wiring (Phase 2)

`compliance/controls.yaml` is the machine-readable source. The evidence
renderer maps each proof/finding's evidence type to controls and prints a
"Framework evidence" section per artifact; `restoregap evidence
--framework <id>` filters an evidence packet to one framework's controls,
in that framework's vocabulary, with restoregap's citation + retrieval date.
Strength values: `direct` (the control asks for exactly this evidence) vs
`supporting` (the evidence helps demonstrate the control). Never render a
`supporting` mapping as if it alone satisfies a control.
