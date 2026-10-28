// Continuous monitoring. On a schedule, re-scans every asset that has
// monitoring on, and raises an alert whenever its shield changes — when a new
// problem appears (the padlock opens) or when it is fixed (the padlock closes
// again). Alerts show in the dashboard and, if LUCENT_ALERT_WEBHOOK is set, are
// also POSTed to that URL (works with Slack, Discord or any webhook).

import { store, type Asset } from "./store.ts";
import { scanOptionsFor } from "./access.ts";
import { runScan, type Shield } from "../engine.ts";

const INTERVAL_MIN = Math.max(5, Number(process.env.LUCENT_SCAN_INTERVAL_MIN) || 360);
// How often to check which assets are due. Defaults to a minute.
const TICK_MS = Math.max(2000, Number(process.env.LUCENT_TICK_MS) || 60_000);
const WEBHOOK = (process.env.LUCENT_ALERT_WEBHOOK ?? "").trim();
const MAX_PER_TICK = 3;

const RANK: Record<Shield, number> = { secure: 0, at_risk: 1, exposed: 2, new: -1, scanning: -1 };

let running = false;

export function dueForScan(asset: Asset): boolean {
  if (!asset.monitor) return false;
  // Never without proof of ownership, and never before the owner's own authorised first scan.
  if (asset.kind === "web" && !asset.verified) return false;
  if (!asset.lastScanAt) return false;
  const age = Date.now() - Date.parse(asset.lastScanAt);
  return age >= INTERVAL_MIN * 60_000;
}

async function dispatch(message: string, extra: object): Promise<void> {
  if (!WEBHOOK) return;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 8000);
  try {
    await fetch(WEBHOOK, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text: message, content: message, ...extra }),
      signal: ctrl.signal,
    });
  } catch {
    /* alerts still land in the dashboard; a webhook failure is not fatal */
  } finally {
    clearTimeout(timer);
  }
}

export function summary(a: Asset): string {
  const c = a.counts, n = c.critical + c.high + c.medium + c.low;
  if (!n) return "no issues";
  return [c.critical && `${c.critical} critical`, c.high && `${c.high} high`, c.medium && `${c.medium} medium`, c.low && `${c.low} low`].filter(Boolean).join(", ");
}

// The webhook belongs to whoever runs this server, so only their own assets are sent to it.
function isAdminOwned(asset: Asset): boolean {
  return !!asset.ownerId && scanOptionsFor(asset.ownerId).admin === true;
}

async function scanOne(asset: Asset): Promise<void> {
  const beforeShield = asset.shield;
  const beforeHighCrit = asset.counts.critical + asset.counts.high;

  if (!store.beginScan(asset.id)) return; // a manual scan is already running
  let updated;
  try {
    const result = await runScan(asset.kind, asset.target, scanOptionsFor(asset.ownerId));
    updated = store.saveScan(asset.id, result);
  } finally {
    store.endScan(asset.id);
  }
  if (!updated) return;
  if (updated.ownerId) store.addEvent({ ownerId: updated.ownerId, assetId: updated.id, assetName: updated.name, type: "autoscan", shield: updated.shield, text: `Protection check of ${updated.name}: ${summary(updated)}` });

  const afterHighCrit = updated.counts.critical + updated.counts.high;
  const worse = RANK[updated.shield] > RANK[beforeShield] || afterHighCrit > beforeHighCrit;
  const recovered = updated.shield === "secure" && (beforeShield === "exposed" || beforeShield === "at_risk");

  // Don't alert on the very first scan (nothing to compare to).
  if (beforeShield === "new") return;

  if (worse) {
    const msg = `🔓 Lucent Shield: "${updated.name}" is now ${updated.shield.toUpperCase()}: ${updated.counts.critical} critical, ${updated.counts.high} high, ${updated.counts.medium} medium.`;
    store.addAlert({ ownerId: updated.ownerId, assetId: updated.id, assetName: updated.name, type: afterHighCrit > beforeHighCrit && RANK[updated.shield] === RANK[beforeShield] ? "new-issues" : "worsened", message: msg });
    if (isAdminOwned(updated)) await dispatch(msg, { asset: updated.name, shield: updated.shield });
  } else if (recovered) {
    const msg = `🔒 Lucent Shield: "${updated.name}" is protected again. All critical and high issues are cleared.`;
    store.addAlert({ ownerId: updated.ownerId, assetId: updated.id, assetName: updated.name, type: "recovered", message: msg });
    if (isAdminOwned(updated)) await dispatch(msg, { asset: updated.name, shield: updated.shield });
  }
}

async function tick(): Promise<void> {
  if (running) return;
  running = true;
  try {
    const due = store.list().filter(dueForScan).slice(0, MAX_PER_TICK);
    for (const asset of due) {
      try {
        await scanOne(asset);
      } catch (err) {
        console.error(`monitor: scan of ${asset.name} failed:`, err instanceof Error ? err.message : err);
      }
    }
  } finally {
    running = false;
  }
}

export function startMonitor(): void {
  const reset = store.resetUnverifiedScans();
  if (reset) console.log(`Monitor: cleared results of ${reset} website(s) scanned before ownership was proven.`);
  console.log(`Monitor: re-scanning watched assets every ${INTERVAL_MIN} min${WEBHOOK ? " (alerts also sent to the configured webhook)" : ""}.`);
  // Check on the tick which assets are due; the interval decides the rest.
  setInterval(() => void tick(), TICK_MS);
  // A first pass shortly after start, so new assets settle in.
  setTimeout(() => void tick(), Math.min(15_000, TICK_MS));
}
