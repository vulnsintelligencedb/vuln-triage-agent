// lib.js — pure, framework-free logic shared by the app and the test suite.
// Everything here is deterministic and unit-tested in /tests.

// Tolerant JSON parser. Model output can be truncated at the token ceiling,
// leaving an incomplete trailing object. This recovers every COMPLETE record
// instead of throwing, so the pipeline degrades gracefully.
export function parseJSON(text) {
  let t = (text || "").replace(/```json/gi, "").replace(/```/g, "").trim();
  const firstArr = t.indexOf("[");
  const firstObj = t.indexOf("{");
  let start = -1;
  if (firstArr === -1) start = firstObj;
  else if (firstObj === -1) start = firstArr;
  else start = Math.min(firstArr, firstObj);
  if (start === -1) throw new Error("no JSON found");
  t = t.slice(start);
  const open = t[0];

  // fast path: trim to last closing bracket, try a clean parse
  try {
    const close = open === "[" ? "]" : "}";
    const end = t.lastIndexOf(close);
    if (end !== -1) return JSON.parse(t.slice(0, end + 1));
  } catch (_) {
    /* fall through to repair */
  }

  // repair path: salvage balanced top-level objects from a truncated array
  if (open === "[") {
    const objs = [];
    let depth = 0, objStart = -1, inStr = false, esc = false;
    for (let i = 1; i < t.length; i++) {
      const ch = t[i];
      if (inStr) {
        if (esc) esc = false;
        else if (ch === "\\") esc = true;
        else if (ch === '"') inStr = false;
        continue;
      }
      if (ch === '"') inStr = true;
      else if (ch === "{") { if (depth === 0) objStart = i; depth++; }
      else if (ch === "}") {
        depth--;
        if (depth === 0 && objStart !== -1) { objs.push(t.slice(objStart, i + 1)); objStart = -1; }
      }
    }
    const arr = [];
    for (const s of objs) { try { arr.push(JSON.parse(s)); } catch (_) {} }
    if (arr.length) return arr;
  }
  throw new Error("could not parse model output");
}

// Applies the corrections the Verify stage found, returning a NEW priority map
// (immutable). Patched groups are flagged so the UI can mark them.
export function applyVerifyCorrections(prioMap, issues) {
  const next = { ...prioMap };
  (issues || []).forEach((iss) => {
    if (iss.corrected_priority && next[iss.group_id]) {
      next[iss.group_id] = {
        ...next[iss.group_id],
        priority: iss.corrected_priority,
        rationale: `${next[iss.group_id].rationale} [patched: ${iss.problem}]`,
        patched: true,
      };
    }
  });
  return next;
}

// Computes the headline noise->signal metrics from triage state.
export function computeMetrics(findings = [], groups = [], prioMap = {}) {
  const real = groups.filter((g) => !g.likely_false_positive);
  const fpGroups = groups.filter((g) => g.likely_false_positive);
  const accountedFor = real.reduce((a, g) => a + (g.count || 1), 0);
  const fpFindings = findings.length - accountedFor;
  const byP = (p) => real.filter((g) => prioMap[g.group_id]?.priority === p).length;
  return {
    raw: findings.length,
    real: real.length,
    fp: Math.max(fpFindings, fpGroups.length),
    p1: byP("P1"),
    p2: byP("P2"),
    p3: byP("P3"),
    p4: byP("P4"),
  };
}
