// Run: npm test   (uses the built-in Node test runner, no extra deps)
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseJSON, applyVerifyCorrections, computeMetrics } from "../src/lib.js";

test("parseJSON: clean array", () => {
  const out = parseJSON('[{"id":"F1"},{"id":"F2"}]');
  assert.equal(out.length, 2);
  assert.equal(out[1].id, "F2");
});

test("parseJSON: strips code fences", () => {
  const out = parseJSON('```json\n[{"id":"F1"}]\n```');
  assert.equal(out[0].id, "F1");
});

test("parseJSON: ignores prose before the JSON", () => {
  const out = parseJSON('Here is the result:\n[{"a":1}]');
  assert.equal(out[0].a, 1);
});

test("parseJSON: recovers from a TRUNCATED array (the prod bug)", () => {
  // model hit the token ceiling mid-third-object
  const truncated = '[{"id":"F1","t":"a"},{"id":"F2","t":"b"},{"id":"F3","t":"inc';
  const out = parseJSON(truncated);
  assert.equal(out.length, 2, "keeps the 2 complete records");
  assert.equal(out[0].id, "F1");
  assert.equal(out[1].id, "F2");
});

test("parseJSON: handles object payloads", () => {
  const out = parseJSON('{"issues":[],"clean":true}');
  assert.equal(out.clean, true);
});

test("parseJSON: throws on garbage", () => {
  assert.throws(() => parseJSON("no json at all here"));
});

test("applyVerifyCorrections: patches priority and flags it", () => {
  const prio = {
    G1: { group_id: "G1", priority: "P3", rationale: "internal only" },
    G2: { group_id: "G2", priority: "P2", rationale: "fine" },
  };
  const issues = [
    { group_id: "G1", problem: "internet-facing critical", corrected_priority: "P1" },
  ];
  const next = applyVerifyCorrections(prio, issues);
  assert.equal(next.G1.priority, "P1");
  assert.equal(next.G1.patched, true);
  assert.match(next.G1.rationale, /patched/);
  assert.equal(next.G2.priority, "P2", "untouched groups unchanged");
  assert.equal(prio.G1.priority, "P3", "original map is not mutated");
});

test("applyVerifyCorrections: no issues is a no-op", () => {
  const prio = { G1: { group_id: "G1", priority: "P2", rationale: "x" } };
  const next = applyVerifyCorrections(prio, []);
  assert.equal(next.G1.priority, "P2");
  assert.equal(next.G1.patched, undefined);
});

test("computeMetrics: noise -> signal counts", () => {
  const findings = [{ id: "F1" }, { id: "F2" }, { id: "F3" }, { id: "F4" }, { id: "F5" }];
  const groups = [
    { group_id: "G1", count: 2, likely_false_positive: false }, // real
    { group_id: "G2", count: 1, likely_false_positive: false }, // real
    { group_id: "G3", count: 2, likely_false_positive: true },  // noise
  ];
  const prio = {
    G1: { priority: "P1" },
    G2: { priority: "P3" },
  };
  const m = computeMetrics(findings, groups, prio);
  assert.equal(m.raw, 5);
  assert.equal(m.real, 2);
  assert.equal(m.fp, 2, "5 raw minus 3 accounted-for in real groups");
  assert.equal(m.p1, 1);
  assert.equal(m.p3, 1);
  assert.equal(m.p2, 0);
});
