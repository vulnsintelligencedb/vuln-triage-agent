import React, { useState, useRef, useEffect } from "react";
import { parseJSON, applyVerifyCorrections, computeMetrics } from "./lib.js";
import { SAMPLE_FINDINGS, SAMPLE_CONTEXT } from "./sampleData.js";

// ─────────────────────────────────────────────────────────────────────────────
// VULN TRIAGE & REMEDIATION AGENT
//
// PITCH: Scanners (Burp, Nuclei, Nessus) FIND vulnerabilities. They don't TRIAGE.
// A human spends days deduping, killing false positives, prioritizing by real
// exposure, and writing fixes. This agent runs that whole pipeline autonomously,
// audits its own work, and emits a decision-ready remediation queue.
//
// Claude runs a visible 7-stage orchestration:
//   plan → normalize → dedupe/FP → prioritize → VERIFY(self-correct) → remediate → self-grade
//
// The model is set server-side (server.js, env CLAUDE_MODEL, default claude-opus-4-8)
// so the API key never reaches the browser. The UI fetches the active model name.
// ─────────────────────────────────────────────────────────────────────────────

const C = {
  shell: "#0E1117",
  panel: "#161B24",
  panel2: "#1C232E",
  line: "#2A3340",
  ink: "#E6EAF0",
  inkDim: "#8A95A6",
  inkFaint: "#5C6675",
  p1: "#FF5C5C",
  p2: "#FFA63D",
  p3: "#4FA8FF",
  p4: "#6B7787",
  ok: "#3FD0A6",
  fp: "#A06BFF",
};

const PRIO = {
  P1: { c: C.p1, label: "Fix now" },
  P2: { c: C.p2, label: "This sprint" },
  P3: { c: C.p3, label: "Backlog" },
  P4: { c: C.p4, label: "Accept / defer" },
};


const STAGES = [
  { key: "plan", name: "Plan", verb: "Reading the scan and planning triage" },
  { key: "normalize", name: "Normalize", verb: "Parsing raw findings into structured records" },
  { key: "dedupe", name: "Dedupe & false-positives", verb: "Clustering duplicates, flagging noise" },
  { key: "prioritize", name: "Prioritize", verb: "Ranking by exploitability + exposure" },
  { key: "verify", name: "Verify", verb: "Auditing its own triage for gaps" },
  { key: "remediate", name: "Remediate", verb: "Drafting fixes and tickets" },
  { key: "grade", name: "Self-grade", verb: "Scoring the run against a rubric" },
];

const SYSTEM =
  "You are a vulnerability triage and remediation engine for a defensive security team. " +
  "You produce triage, prioritization, and remediation guidance only — never exploit code or attack steps. " +
  "Follow the requested output format exactly. Be terse. When asked for JSON, return ONLY valid JSON with no prose and no code fences.";

async function callClaude(prompt) {
  const res = await fetch("/api/claude", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ system: SYSTEM, prompt }),
  });
  if (!res.ok) throw new Error(`API ${res.status}`);
  const data = await res.json();
  return (data.content || [])
    .filter((b) => b.type === "text")
    .map((b) => b.text)
    .join("\n");
}


export default function TriageAgent() {
  const [raw, setRaw] = useState("");
  const [ctx, setCtx] = useState("");
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");
  const [stageState, setStageState] = useState({});
  const [r, setR] = useState({});
  const [openGroup, setOpenGroup] = useState(null);
  const [modelName, setModelName] = useState("claude-opus-4-8");
  const resultsRef = useRef(null);

  useEffect(() => {
    fetch("/api/model")
      .then((res) => res.json())
      .then((d) => d.model && setModelName(d.model))
      .catch(() => {});
  }, []);

  const setStage = (key, status) =>
    setStageState((s) => ({ ...s, [key]: status }));

  async function run() {
    const findings = raw.trim();
    if (!findings) {
      setError("Paste scanner output first, or load the sample scan.");
      return;
    }
    setError("");
    setRunning(true);
    setR({});
    setOpenGroup(null);
    setStageState(Object.fromEntries(STAGES.map((s) => [s.key, "pending"])));

    const acc = {};
    try {
      // 1. PLAN
      setStage("plan", "running");
      acc.plan = await callClaude(
        `Raw scanner output:\n<findings>\n${findings}\n</findings>\n\nIn 2-3 short sentences: which scanner(s)/format this looks like, roughly how many raw findings, and your triage plan. Plain text only.`
      );
      setStage("plan", "done");
      setR({ ...acc });

      // 2. NORMALIZE
      setStage("normalize", "running");
      acc.findings = parseJSON(
        await callClaude(
          `Parse this raw scanner output into structured findings.\n<findings>\n${findings}\n</findings>\n\nReturn ONLY minified JSON (no whitespace, no newlines), a single array. Each item: {"id":"F1","title":"short","severity":"critical|high|medium|low|info","asset":"host or url","cve":"CVE-... or empty"}. One entry per raw line; keep duplicates as separate entries.`
        )
      );
      setStage("normalize", "done");
      setR({ ...acc });

      // 3. DEDUPE & FALSE POSITIVES
      setStage("dedupe", "running");
      acc.groups = parseJSON(
        await callClaude(
          `Findings:\n${JSON.stringify(acc.findings)}\n\nGroup duplicates (same vuln class on same/similar asset) and flag likely false positives or pure-noise/info items. Return ONLY minified JSON (no whitespace), a single array. Each group: {"group_id":"G1","title":"short","severity":"critical|high|medium|low|info","asset":"...","member_ids":["F1","F3"],"count":2,"cve":"... or empty","likely_false_positive":true|false,"fp_reason":"<=12 words or empty"}.`
        )
      );
      setStage("dedupe", "done");
      setR({ ...acc });

      // 4. PRIORITIZE
      setStage("prioritize", "running");
      const prio = parseJSON(
        await callClaude(
          `Deduped groups:\n${JSON.stringify(
            acc.groups.map((g) => ({
              group_id: g.group_id,
              title: g.title,
              severity: g.severity,
              asset: g.asset,
              fp: g.likely_false_positive,
            }))
          )}\n\nAsset context:\n${ctx.trim() || "none provided"}\n\nAssign triage priority using severity + exploitability + asset exposure + data sensitivity. Return ONLY a JSON array. Each: {"group_id":"G1","priority":"P1|P2|P3|P4","rationale":"<=24 words"}. P1=fix now (exploitable + exposed/sensitive), P4=accept/defer (noise, low-risk, decommissioning).`
        )
      );
      acc.prio = Object.fromEntries(prio.map((p) => [p.group_id, p]));
      setStage("prioritize", "done");
      setR({ ...acc });

      // 5. VERIFY (self-correction)
      setStage("verify", "running");
      const verify = parseJSON(
        await callClaude(
          `Audit your own triage for rigor.\nGroups:\n${JSON.stringify(
            acc.groups.map((g) => ({
              group_id: g.group_id,
              title: g.title,
              severity: g.severity,
              asset: g.asset,
              fp: g.likely_false_positive,
            }))
          )}\nPriorities:\n${JSON.stringify(prio)}\n\nFind: any group missing a priority, any P1 lacking strong justification, any false-positive flag that looks wrong, any exposed+sensitive critical rated too low. Return ONLY JSON: {"issues":[{"group_id":"...","problem":"<=16 words","corrected_priority":"P1|P2|P3|P4 or empty"}],"clean":true|false}.`
        )
      );
      acc.verify = verify;
      // apply corrections via the tested pure helper — the patch is real and visible
      acc.prio = applyVerifyCorrections(acc.prio, verify.issues);
      setStage("verify", "done");
      setR({ ...acc });

      // 6. REMEDIATE
      setStage("remediate", "running");
      const actionable = acc.groups.filter((g) => !g.likely_false_positive);
      const rem = parseJSON(
        await callClaude(
          `Produce remediation for these prioritized findings.\n${JSON.stringify(
            actionable.map((g) => ({
              group_id: g.group_id,
              title: g.title,
              cve: g.cve,
              priority: acc.prio[g.group_id]?.priority,
            }))
          )}\n\nReturn ONLY minified JSON (no whitespace), a single array. Each: {"group_id":"G1","owner":"team","fix":"<=24 word defensive remediation steps","validation":"<=12 word how to confirm fixed"}. Defensive fixes only — no exploit or attack steps.`
        )
      );
      acc.rem = Object.fromEntries(rem.map((x) => [x.group_id, x]));
      setStage("remediate", "done");
      setR({ ...acc });

      // 7. SELF-GRADE
      setStage("grade", "running");
      const raw_n = acc.findings.length;
      const grp_n = acc.groups.length;
      const fp_n = acc.groups.filter((g) => g.likely_false_positive).length;
      const p1_n = Object.values(acc.prio).filter((p) => p.priority === "P1").length;
      const issues_n = (verify.issues || []).length;
      acc.grade = parseJSON(
        await callClaude(
          `Grade your own triage run on this rubric, 0-5 each: noise_reduction, dedup_accuracy, prioritization_soundness, remediation_actionability. Context: raw=${raw_n}, groups=${grp_n}, false_positives=${fp_n}, P1=${p1_n}, issues_found_in_verify=${issues_n}. Return ONLY JSON: {"scores":{"noise_reduction":n,"dedup_accuracy":n,"prioritization_soundness":n,"remediation_actionability":n},"overall":n,"note":"<=18 words"}.`
        )
      );
      setStage("grade", "done");
      setR({ ...acc });
      setTimeout(
        () => resultsRef.current?.scrollIntoView({ behavior: "smooth" }),
        120
      );
    } catch (e) {
      setError(`Stage failed: ${e.message}. Hit Run again to retry.`);
      setStageState((s) => {
        const next = { ...s };
        for (const st of STAGES) if (next[st.key] === "running") next[st.key] = "error";
        return next;
      });
    } finally {
      setRunning(false);
    }
  }

  function loadSample() {
    setRaw(SAMPLE_FINDINGS);
    setCtx(SAMPLE_CONTEXT);
    setError("");
  }

  function exportReport() {
    if (!r.groups) return;
    const lines = [];
    lines.push(`# Vulnerability Triage Report`);
    lines.push(`_Generated by autonomous triage agent — ${new Date().toLocaleString()}_\n`);
    const m = metrics();
    lines.push(
      `**${m.raw} raw findings → ${m.real} real issues** (${m.fp} duplicates/false-positives filtered)`
    );
    lines.push(`P1: ${m.p1} · P2: ${m.p2} · P3: ${m.p3} · P4: ${m.p4}\n`);
    ["P1", "P2", "P3", "P4"].forEach((p) => {
      const gs = r.groups.filter(
        (g) => !g.likely_false_positive && r.prio[g.group_id]?.priority === p
      );
      if (!gs.length) return;
      lines.push(`## ${p} — ${PRIO[p].label}`);
      gs.forEach((g) => {
        lines.push(`### ${g.title}${g.cve ? ` (${g.cve})` : ""}`);
        lines.push(`- Asset: ${g.asset} · ${g.count} occurrence(s)`);
        lines.push(`- Why: ${r.prio[g.group_id]?.rationale || ""}`);
        if (r.rem?.[g.group_id]) {
          lines.push(`- Owner: ${r.rem[g.group_id].owner}`);
          lines.push(`- Fix: ${r.rem[g.group_id].fix}`);
          lines.push(`- Verify fix: ${r.rem[g.group_id].validation}`);
        }
        lines.push("");
      });
    });
    const fps = r.groups.filter((g) => g.likely_false_positive);
    if (fps.length) {
      lines.push(`## Filtered (duplicates / false positives)`);
      fps.forEach((g) => lines.push(`- ${g.title} — ${g.fp_reason || "noise"}`));
    }
    const blob = new Blob([lines.join("\n")], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "triage-report.md";
    a.click();
    URL.revokeObjectURL(url);
  }

  function metrics() {
    if (!r.groups) return {};
    return computeMetrics(r.findings || [], r.groups, r.prio || {});
  }

  const m = metrics();
  const done = stageState.grade === "done";

  return (
    <div style={{ background: C.shell, color: C.ink, minHeight: "100%", fontFamily: "ui-sans-serif, system-ui, -apple-system, sans-serif" }}>
      <style>{`
        .ta-mono { font-family: ui-monospace, "SF Mono", "Cascadia Mono", Menlo, monospace; }
        .ta-btn { cursor:pointer; border:none; transition:filter .15s, opacity .15s; }
        .ta-btn:hover:not(:disabled){ filter:brightness(1.12); }
        .ta-btn:disabled{ opacity:.5; cursor:default; }
        .ta-ta { width:100%; background:${C.shell}; color:${C.ink}; border:1px solid ${C.line}; border-radius:8px; padding:11px 12px; font-size:12.5px; resize:vertical; outline:none; }
        .ta-ta:focus{ border-color:${C.p3}; }
        .ta-row:hover{ background:${C.panel2}; }
        @keyframes ta-pulse { 0%,100%{opacity:.35} 50%{opacity:1} }
        .ta-pulse { animation: ta-pulse 1.1s ease-in-out infinite; }
        @keyframes ta-grow { from{transform:scaleX(0)} to{transform:scaleX(1)} }
      `}</style>

      <div style={{ maxWidth: 1040, margin: "0 auto", padding: "26px 22px 70px" }}>
        {/* HEADER */}
        <div style={{ display: "flex", alignItems: "baseline", gap: 12, flexWrap: "wrap" }}>
          <div className="ta-mono" style={{ fontSize: 11, letterSpacing: 2, color: C.ok }}>
            TRIAGE&nbsp;AGENT
          </div>
          <div style={{ height: 14, width: 1, background: C.line }} />
          <div className="ta-mono" style={{ fontSize: 11, color: C.inkFaint }}>
            scanners find · we decide
          </div>
        </div>
        <h1 style={{ fontSize: 27, fontWeight: 650, margin: "10px 0 6px", letterSpacing: -0.5, lineHeight: 1.15 }}>
          Turn a noisy scan dump into a<br />decision-ready remediation queue
        </h1>
        <p style={{ color: C.inkDim, fontSize: 13.5, margin: 0, maxWidth: 640 }}>
          Burp, Nuclei, and Nessus <em>find</em> vulnerabilities — then a human burns days
          deduping, killing false positives, and ranking what actually matters. This agent
          runs that pipeline autonomously and audits its own work.
        </p>

        {/* INPUT */}
        <div style={{ display: "grid", gridTemplateColumns: "1.4fr 1fr", gap: 14, marginTop: 22 }}>
          <div>
            <label style={{ fontSize: 11, color: C.inkDim, letterSpacing: 0.5 }}>SCANNER OUTPUT</label>
            <textarea
              className="ta-ta ta-mono"
              style={{ marginTop: 6, minHeight: 150 }}
              placeholder="Paste Nuclei / Burp / Nessus findings…"
              value={raw}
              onChange={(e) => setRaw(e.target.value)}
            />
          </div>
          <div>
            <label style={{ fontSize: 11, color: C.inkDim, letterSpacing: 0.5 }}>
              ASSET CONTEXT <span style={{ color: C.inkFaint }}>(optional, sharpens priority)</span>
            </label>
            <textarea
              className="ta-ta"
              style={{ marginTop: 6, minHeight: 150 }}
              placeholder="Which hosts are internet-facing? What data do they hold?"
              value={ctx}
              onChange={(e) => setCtx(e.target.value)}
            />
          </div>
        </div>

        <div style={{ display: "flex", gap: 10, marginTop: 14, alignItems: "center", flexWrap: "wrap" }}>
          <button
            className="ta-btn ta-mono"
            onClick={run}
            disabled={running}
            style={{ background: C.ok, color: "#06231B", fontWeight: 700, fontSize: 13, padding: "10px 22px", borderRadius: 8, letterSpacing: 0.4 }}
          >
            {running ? "RUNNING…" : "▶  RUN TRIAGE"}
          </button>
          <button
            className="ta-btn"
            onClick={loadSample}
            disabled={running}
            style={{ background: C.panel2, color: C.ink, fontSize: 12.5, padding: "10px 16px", borderRadius: 8, border: `1px solid ${C.line}` }}
          >
            Load sample scan
          </button>
          {done && (
            <button
              className="ta-btn"
              onClick={exportReport}
              style={{ background: "transparent", color: C.p3, fontSize: 12.5, padding: "10px 16px", borderRadius: 8, border: `1px solid ${C.p3}` }}
            >
              ⬇ Export report
            </button>
          )}
          {error && <span style={{ color: C.p1, fontSize: 12.5 }}>{error}</span>}
        </div>

        {/* PIPELINE — the audit trail */}
        {Object.keys(stageState).length > 0 && (
          <div style={{ marginTop: 24, background: C.panel, border: `1px solid ${C.line}`, borderRadius: 12, padding: "16px 18px" }}>
            <div className="ta-mono" style={{ fontSize: 10.5, color: C.inkFaint, letterSpacing: 1.5, marginBottom: 12 }}>
              CLAUDE&nbsp;ORCHESTRATION&nbsp;·&nbsp;{modelName}
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
              {STAGES.map((s, i) => {
                const st = stageState[s.key] || "pending";
                const color = st === "done" ? C.ok : st === "running" ? C.p3 : st === "error" ? C.p1 : C.inkFaint;
                const isVerifyPatched = s.key === "verify" && st === "done" && (r.verify?.issues?.length > 0);
                return (
                  <div key={s.key} style={{ display: "flex", alignItems: "center", gap: 12, padding: "7px 0" }}>
                    <span className="ta-mono" style={{ fontSize: 10, color: C.inkFaint, width: 18 }}>{i + 1}</span>
                    <span
                      className={st === "running" ? "ta-pulse" : ""}
                      style={{ width: 9, height: 9, borderRadius: 9, background: color, flexShrink: 0, boxShadow: st === "running" ? `0 0 8px ${color}` : "none" }}
                    />
                    <span style={{ fontSize: 13, color: st === "pending" ? C.inkFaint : C.ink, fontWeight: st === "running" ? 600 : 500, width: 200 }}>
                      {s.name}
                    </span>
                    <span style={{ fontSize: 12, color: C.inkDim, flex: 1 }}>
                      {st === "running" ? s.verb + "…" : st === "done" ? (isVerifyPatched ? `Found ${r.verify.issues.length} gap(s) — patched` : "✓") : st === "error" ? "error — retry" : ""}
                    </span>
                  </div>
                );
              })}
            </div>
            {r.plan && (
              <div style={{ marginTop: 12, paddingTop: 12, borderTop: `1px solid ${C.line}`, fontSize: 12.5, color: C.inkDim, lineHeight: 1.5 }}>
                <span className="ta-mono" style={{ color: C.ok, fontSize: 10.5 }}>PLAN&nbsp;»&nbsp;</span>
                {r.plan}
              </div>
            )}
          </div>
        )}

        {/* RESULTS */}
        {r.groups && (
          <div ref={resultsRef} style={{ marginTop: 26 }}>
            {/* noise → signal metrics */}
            <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "stretch" }}>
              <Metric big label="raw findings" value={m.raw} color={C.inkDim} />
              <div style={{ display: "flex", alignItems: "center", color: C.inkFaint, fontSize: 22 }}>→</div>
              <Metric big label="real issues" value={m.real} color={C.ok} />
              <Metric label="filtered" value={m.fp} color={C.fp} sub="dupes / false +" />
              <div style={{ flex: 1, minWidth: 200, background: C.panel, border: `1px solid ${C.line}`, borderRadius: 10, padding: "12px 14px", display: "flex", gap: 14, alignItems: "center", justifyContent: "space-around" }}>
                {["P1", "P2", "P3", "P4"].map((p) => (
                  <div key={p} style={{ textAlign: "center" }}>
                    <div className="ta-mono" style={{ color: PRIO[p].c, fontSize: 20, fontWeight: 700 }}>{m[p.toLowerCase()]}</div>
                    <div style={{ fontSize: 9.5, color: C.inkFaint, marginTop: 2 }}>{p}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* prioritized queue */}
            {["P1", "P2", "P3", "P4"].map((p) => {
              const gs = r.groups.filter((g) => !g.likely_false_positive && r.prio?.[g.group_id]?.priority === p);
              if (!gs.length) return null;
              return (
                <div key={p} style={{ marginTop: 18 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                    <span className="ta-mono" style={{ background: PRIO[p].c, color: "#0B0E13", fontWeight: 700, fontSize: 11, padding: "2px 8px", borderRadius: 5 }}>{p}</span>
                    <span style={{ fontSize: 12.5, color: C.inkDim }}>{PRIO[p].label}</span>
                  </div>
                  {gs.map((g) => {
                    const pr = r.prio[g.group_id];
                    const rem = r.rem?.[g.group_id];
                    const open = openGroup === g.group_id;
                    return (
                      <div key={g.group_id} className="ta-row" style={{ borderLeft: `3px solid ${PRIO[p].c}`, background: C.panel, borderRadius: "0 8px 8px 0", marginBottom: 6, cursor: "pointer" }} onClick={() => setOpenGroup(open ? null : g.group_id)}>
                        <div style={{ padding: "11px 14px", display: "flex", alignItems: "center", gap: 10 }}>
                          <span style={{ fontSize: 13.5, fontWeight: 550, flex: 1 }}>
                            {g.title}
                            {g.cve && <span className="ta-mono" style={{ color: C.p2, fontSize: 11, marginLeft: 8 }}>{g.cve}</span>}
                            {pr?.patched && <span className="ta-mono" style={{ color: C.ok, fontSize: 10, marginLeft: 8, border: `1px solid ${C.ok}`, padding: "1px 5px", borderRadius: 4 }}>verify-patched</span>}
                          </span>
                          <span className="ta-mono" style={{ fontSize: 11, color: C.inkFaint }}>{g.asset}</span>
                          {g.count > 1 && <span className="ta-mono" style={{ fontSize: 10.5, color: C.inkDim, background: C.panel2, padding: "1px 6px", borderRadius: 4 }}>×{g.count}</span>}
                          <span style={{ color: C.inkFaint, fontSize: 11 }}>{open ? "▾" : "▸"}</span>
                        </div>
                        {open && (
                          <div style={{ padding: "0 14px 13px", fontSize: 12.5, color: C.inkDim, lineHeight: 1.55 }}>
                            <div style={{ marginBottom: 6 }}><span style={{ color: C.inkFaint }}>Why this priority: </span>{pr?.rationale}</div>
                            {rem && (
                              <div style={{ background: C.shell, border: `1px solid ${C.line}`, borderRadius: 7, padding: "10px 12px", marginTop: 8 }}>
                                <div><span className="ta-mono" style={{ color: C.ok, fontSize: 10.5 }}>OWNER&nbsp;</span>{rem.owner}</div>
                                <div style={{ marginTop: 5 }}><span className="ta-mono" style={{ color: C.ok, fontSize: 10.5 }}>FIX&nbsp;&nbsp;&nbsp;&nbsp;</span>{rem.fix}</div>
                                <div style={{ marginTop: 5 }}><span className="ta-mono" style={{ color: C.ok, fontSize: 10.5 }}>VERIFY&nbsp;</span>{rem.validation}</div>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              );
            })}

            {/* filtered noise */}
            {r.groups.some((g) => g.likely_false_positive) && (
              <div style={{ marginTop: 20 }}>
                <div className="ta-mono" style={{ fontSize: 10.5, color: C.fp, letterSpacing: 1, marginBottom: 8 }}>FILTERED&nbsp;—&nbsp;DUPLICATES&nbsp;/&nbsp;FALSE&nbsp;POSITIVES</div>
                {r.groups.filter((g) => g.likely_false_positive).map((g) => (
                  <div key={g.group_id} style={{ fontSize: 12.5, color: C.inkFaint, padding: "4px 0" }}>
                    <span style={{ textDecoration: "line-through", color: C.inkDim }}>{g.title}</span>
                    {g.fp_reason && <span style={{ marginLeft: 8 }}>— {g.fp_reason}</span>}
                  </div>
                ))}
              </div>
            )}

            {/* self-grade */}
            {r.grade && (
              <div style={{ marginTop: 24, background: C.panel, border: `1px solid ${C.line}`, borderRadius: 12, padding: "16px 18px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 14 }}>
                  <span className="ta-mono" style={{ fontSize: 10.5, color: C.inkFaint, letterSpacing: 1.5 }}>SELF-GRADE&nbsp;·&nbsp;CLAUDE&nbsp;SCORED&nbsp;ITS&nbsp;OWN&nbsp;RUN</span>
                  <span><span className="ta-mono" style={{ fontSize: 22, fontWeight: 700, color: C.ok }}>{r.grade.overall}</span><span style={{ color: C.inkFaint, fontSize: 13 }}>/5</span></span>
                </div>
                {Object.entries(r.grade.scores || {}).map(([k, v]) => (
                  <div key={k} style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 7 }}>
                    <span style={{ fontSize: 12, color: C.inkDim, width: 200 }}>{k.replace(/_/g, " ")}</span>
                    <div style={{ flex: 1, height: 6, background: C.shell, borderRadius: 4, overflow: "hidden" }}>
                      <div style={{ height: "100%", width: `${(v / 5) * 100}%`, background: C.ok, borderRadius: 4, transformOrigin: "left", animation: "ta-grow .5s ease-out" }} />
                    </div>
                    <span className="ta-mono" style={{ fontSize: 11.5, color: C.ink, width: 24 }}>{v}/5</span>
                  </div>
                ))}
                {r.grade.note && <div style={{ marginTop: 10, fontSize: 12.5, color: C.inkDim, fontStyle: "italic" }}>{r.grade.note}</div>}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function Metric({ label, value, color, big, sub }) {
  return (
    <div style={{ background: "#161B24", border: "1px solid #2A3340", borderRadius: 10, padding: big ? "14px 20px" : "12px 16px", minWidth: big ? 110 : 90, textAlign: "center" }}>
      <div className="ta-mono" style={{ fontSize: big ? 34 : 24, fontWeight: 700, color, lineHeight: 1 }}>{value}</div>
      <div style={{ fontSize: 10.5, color: "#8A95A6", marginTop: 5 }}>{label}</div>
      {sub && <div style={{ fontSize: 9, color: "#5C6675", marginTop: 1 }}>{sub}</div>}
    </div>
  );
}
