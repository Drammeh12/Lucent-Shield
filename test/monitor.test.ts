// Background protection never scans anything the owner has not proven and authorised.

import { test } from "node:test";
import assert from "node:assert/strict";
import { dueForScan } from "../src/server/monitor.ts";
import type { Asset } from "../src/server/store.ts";

const base: Asset = {
  id: "a", name: "site", kind: "web", target: "https://site.example", authorized: true, verified: true, verifyToken: "t",
  monitor: true, createdAt: "2026-01-01T00:00:00Z", lastScanAt: "2020-01-01T00:00:00Z", shield: "secure",
  counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, findings: [],
};

test("a protected, verified, previously scanned asset is re-checked when due", () => {
  assert.equal(dueForScan(base), true);
});

test("never scanned in the background: unprotected, unverified, or never scanned by its owner", () => {
  assert.equal(dueForScan({ ...base, monitor: false }), false);
  assert.equal(dueForScan({ ...base, verified: false }), false);
  assert.equal(dueForScan({ ...base, lastScanAt: null }), false);
});

test("not due again before the interval", () => {
  assert.equal(dueForScan({ ...base, lastScanAt: new Date().toISOString() }), false);
});
