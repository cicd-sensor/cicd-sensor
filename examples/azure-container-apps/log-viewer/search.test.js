import test from "node:test";
import assert from "node:assert/strict";
import { gzipSync } from "node:zlib";
import { datePrefixes, parseJSONL, matches } from "./search.js";

test("datePrefixes expands days and types", () => {
  const p = datePrefixes("cicd-sensor/", ["summary", "detection"], new Date("2026-11-01T10:00:00Z"), new Date("2026-11-02T01:00:00Z"));
  assert.deepEqual(p, [
    "cicd-sensor/summary/dt=2026-11-01/",
    "cicd-sensor/detection/dt=2026-11-01/",
    "cicd-sensor/summary/dt=2026-11-02/",
    "cicd-sensor/detection/dt=2026-11-02/",
  ]);
});

test("parseJSONL skips malformed lines", () => {
  const buf = gzipSync('{"a":1}\nnot json\n\n{"a":2}\n');
  assert.equal(parseJSONL(buf).length, 2);
});

test("matches filters by time and keyword", () => {
  const item = { raw: '{"timestamp":"2026-11-03T06:00:00Z","x":"Curl"}', rec: { timestamp: "2026-11-03T06:00:00Z" } };
  assert.ok(matches(item, { keyword: "curl" }));
  assert.ok(!matches(item, { keyword: "wget" }));
  assert.ok(!matches(item, { from: new Date("2026-11-03T07:00:00Z") }));
  assert.ok(!matches(item, { to: new Date("2026-11-03T05:00:00Z") }));
});
