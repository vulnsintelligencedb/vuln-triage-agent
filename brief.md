# Brief — Vuln Triage Agent

**Problem.** Vulnerability scanners (Burp, Nuclei, Nessus) produce hundreds of raw findings per scan. Security teams spend days manually deduping them, discarding false positives, judging which findings are actually exploitable given the environment, and turning the survivors into assigned, actionable fixes. The scanners find; a human does the slow, expensive triage.

**Solution.** An autonomous agent that runs the entire triage-to-remediation workflow and audits its own work. Input: raw scanner output + a short description of the environment (which hosts are exposed, what data they hold). Output: a prioritized, owner-assigned, self-verified remediation queue plus an exportable report.

**Why it's not a scanner / not a dashboard.** It does not scan — it consumes scanner output and makes decisions. The deliverable is the completed triage packet (an exported remediation report), not a screen of charts. The product is the workflow.

**How Claude does the work (orchestration).** Seven sequential Opus 4.8 calls, each single-purpose with a strict JSON contract:

1. **Plan** — identify the scanner format and outline the triage approach.
2. **Normalize** — parse unstructured scanner text into structured findings.
3. **Dedupe & false-positives** — cluster duplicates, flag noise.
4. **Prioritize** — rank by exploitability + asset exposure + data sensitivity.
5. **Verify** — audit stages 3–4, return errors, corrections applied programmatically.
6. **Remediate** — owner, fix steps, validation step per issue (defensive only).
7. **Self-grade** — score the run against a rubric.

**Differentiator.** The Verify stage makes this an agent, not a prompt: Claude catches and fixes its own triage mistakes before deciding. A tolerant parser keeps the pipeline running even if a response is truncated.

**Impact.** "Hundreds of raw findings → a handful of real, prioritized issues" in under a minute, with an audit trail. Replaces a multi-day manual cycle.

**Scope & safety.** Defensive triage and remediation guidance only. No exploit or attack-step generation. Synthetic data only in the public repo.
