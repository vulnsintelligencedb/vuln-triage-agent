# Session Log — Vuln Triage Agent

A condensed record of how this project was directed and built with Claude (Opus 4.8) during the event. It captures the decisions, the orchestration strategy, and the one real bug we hit and fixed — not a raw transcript.

---

## 1. Framing the problem

We started from a constraint, not a feature: pick a workflow that genuinely takes days by hand and is a poor fit for a chatbot. Vulnerability triage fit. Scanners (Burp, Nuclei, Nessus) emit hundreds of raw findings per run — duplicates, false positives, noise — and a human spends days deciding what actually matters. The scanners find; nobody triages.

Design rule we set early: the product is the **workflow that completes the task**, not a dashboard. The deliverable is an exported remediation packet. We kept the scope strictly **defensive** — triage, prioritization, and remediation guidance only, never exploit generation — and enforced that in a shared system prompt.

## 2. Orchestration strategy

We rejected a single monolithic prompt in favor of a **sequential multi-stage agent pipeline with a self-verification loop**. Seven stages, each a separate Opus 4.8 call with one responsibility and a strict structured-output (minified JSON) contract:

1. **Plan** — identify the scanner format, outline the triage approach.
2. **Normalize** — parse unstructured scanner text into structured findings.
3. **Dedupe & false-positives** — cluster duplicates, flag noise.
4. **Prioritize** — rank by exploitability + asset exposure + data sensitivity, not raw severity.
5. **Verify** — the model audits its own stage 3–4 output, returns the errors it finds; corrections are applied programmatically.
6. **Remediate** — owner, fix steps, validation step per issue.
7. **Self-grade** — score the run against a rubric (`rubric.md`).

The **Verify** stage is the heart of it: it makes the system an agent rather than a prompt, because the model catches and patches its own mistakes (e.g. an internet-facing critical it under-rated) before the final decision.

## 3. Key engineering decisions Claude drove

- **Prompt chain** — one system prompt enforcing the defensive constraint and JSON contract; seven terse per-stage prompts. Output forced to minified JSON to stay within token limits.
- **Server-side model** — the API key never reaches the browser. A small Express proxy injects `ANTHROPIC_API_KEY` from the environment and forwards to the API; the deployed model defaults to `claude-opus-4-8`.
- **Pure, tested core** — parser, verify-correction, and metrics logic extracted into a framework-free module with a unit-test suite.

## 4. The bug we caught and fixed

During testing the pipeline failed with `Unexpected end of JSON input`. Diagnosis: with ~20 findings, a stage's JSON output ran past the token ceiling and was truncated mid-array, so a strict parse threw.

Fix, in two parts:
1. A **tolerant parser** that recovers every complete record from a truncated array and drops the incomplete trailing one, so the pipeline degrades gracefully instead of crashing.
2. **Tighter output** — minified JSON and dropping an unused field so arrays stay under budget.

Both behaviors are covered by the test suite (`tests/lib.test.js`), including an explicit truncation-recovery case.

## 5. Deploy

Deployed as a single Node service (frontend build + proxy) with one environment variable (`ANTHROPIC_API_KEY`). The server logs its active model on startup, confirming the run is on `claude-opus-4-8`.

---

**Repo:** https://github.com/vulnsintelligencedb/vuln-triage-agent
**Brief:** ./brief.md · **Rubric:** ./rubric.md
