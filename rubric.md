# Rubric — Vuln Triage Agent

This is the rubric Claude scores its own run against in the **Self-grade** stage. Each dimension is scored 0–5; `overall` is the mean.

| Dimension | What a 5 looks like |
|---|---|
| **noise_reduction** | Raw findings collapsed to a small set of real issues; pure-noise/info items removed. |
| **dedup_accuracy** | Genuine duplicates merged; distinct issues kept separate; no real finding lost to over-merging. |
| **prioritization_soundness** | Priority reflects exploitability AND asset exposure/data sensitivity, not just raw scanner severity. Internet-facing + sensitive criticals rank above internal or decommissioning hosts. |
| **remediation_actionability** | Each issue has a plausible owner, a concrete defensive fix, and a way to verify the fix. No exploit steps. |

## Definition of done (objective checks)

A run is complete only when **all** hold:

- Every normalized finding belongs to exactly one group (deduped or flagged false-positive).
- Every non-false-positive group has a priority (P1–P4) with a stated rationale.
- Every actionable group has a remediation entry (owner + fix + validation).
- The Verify stage has run and any corrections it returned have been applied.
- A self-grade has been produced.

## Priority definitions

- **P1 — fix now:** exploitable and exposed/sensitive (e.g. internet-facing RCE on a host handling customer data).
- **P2 — this sprint:** real risk, partially mitigated by exposure or difficulty.
- **P3 — backlog:** low exploitability or low-value asset.
- **P4 — accept / defer:** noise, near-zero risk, or asset being decommissioned.

## Verify-stage targets (what the self-audit looks for)

- Any group with no priority.
- Any P1 lacking strong justification.
- Any false-positive flag that looks wrong.
- Any exposed + sensitive critical rated too low.
