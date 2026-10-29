/**
 * Plans for Lucent Shield.
 *
 *  - Free, for everyone: 3 scans, and monitoring of 1 asset for 24 hours, so
 *    anyone can see what Lucent Shield finds before paying.
 *  - Bash Cloud welcome: an account that proves it owns a site hosted on Bash
 *    Cloud gets 14 days of Lucent Shield free (50 scans, 3 monitored assets),
 *    then 25% off any plan for as long as it hosts with Bash Cloud.
 *  - Paid plans, monthly, in naira or US dollars.
 *  - The admin has no limits.
 *
 * Until online payment is switched on, the admin sets an account's plan from
 * the Admin page after payment. LUCENT_LIMITS=off removes every limit
 * (development, or a private installation).
 */
import type { User } from "./store.ts";

export type PaidCode = "solo" | "team" | "business";
export type PlanCode = "free" | "welcome" | PaidCode | "admin";

export interface PaidPlan { code: PaidCode; name: string; scans: number; monitored: number; ngn: number; usd: number; blurb: string }

export const PAID_PLANS: PaidPlan[] = [
  { code: "solo", name: "Solo", scans: 60, monitored: 3, ngn: 5_000, usd: 4, blurb: "One developer or a small business website." },
  { code: "team", name: "Team", scans: 300, monitored: 15, ngn: 15_000, usd: 12, blurb: "A team with several apps and repositories." },
  { code: "business", name: "Business", scans: 1_500, monitored: 50, ngn: 45_000, usd: 35, blurb: "Companies and agencies looking after many sites." },
];

export const FREE = { scans: 3, monitored: 1, monitorHours: 24 };
export const WELCOME = { days: 14, scans: 50, monitored: 3 };
export const BASHCLOUD_DISCOUNT = 25;
const DAY = 86_400_000;

export const limitsOff = () => (process.env.LUCENT_LIMITS ?? "").trim().toLowerCase() === "off";

/** What an account may do right now. */
export interface Entitlement {
  code: PlanCode;
  name: string;
  /** Scans allowed in this period (null: no limit) and used so far. */
  scanLimit: number | null;
  scansUsed: number;
  monitorLimit: number | null;
  /** Free plan only: when the 24 hours of monitoring end (null until started). */
  monitorEndsAt: string | null;
  /** When the welcome period or the paid plan ends. */
  endsAt: string | null;
  /** The account hosts on Bash Cloud (proven by a verified site). */
  bashCloud: boolean;
  /** Discount on paid plans, in percent. */
  discount: number;
  /** The usage period scans are counted in. */
  period: string;
}

export function entitlement(u: User, admin: boolean, now = Date.now()): Entitlement {
  const bashCloud = !!u.bashCloud;
  const discount = bashCloud ? BASHCLOUD_DISCOUNT : 0;
  const base = { bashCloud, discount, monitorEndsAt: null as string | null };
  const used = (period: string) => (u.usage?.period === period ? u.usage.scans : 0);
  if (admin || limitsOff()) return { ...base, code: "admin", name: admin ? "Admin" : "Unlimited", scanLimit: null, scansUsed: 0, monitorLimit: null, endsAt: null, period: "none" };

  const paid = u.plan && Date.parse(u.plan.paidUntil) > now ? PAID_PLANS.find((p) => p.code === u.plan!.code) : undefined;
  if (paid) {
    const period = new Date(now).toISOString().slice(0, 7);
    return { ...base, code: paid.code, name: paid.name, scanLimit: paid.scans, scansUsed: used(period), monitorLimit: paid.monitored, endsAt: u.plan!.paidUntil, period };
  }
  if (u.bashCloud) {
    const ends = Date.parse(u.bashCloud.since) + WELCOME.days * DAY;
    if (ends > now) return { ...base, code: "welcome", name: "Bash Cloud welcome", scanLimit: WELCOME.scans, scansUsed: used("welcome"), monitorLimit: WELCOME.monitored, endsAt: new Date(ends).toISOString(), period: "welcome" };
  }
  const monitorEndsAt = u.freeMonitorAt ? new Date(Date.parse(u.freeMonitorAt) + FREE.monitorHours * 3_600_000).toISOString() : null;
  return { ...base, code: "free", name: "Free", scanLimit: FREE.scans, scansUsed: used("free"), monitorLimit: FREE.monitored, monitorEndsAt, endsAt: null, period: "free" };
}

/** Why a scan cannot run, or null if it can. */
export function scanBlocked(e: Entitlement): string | null {
  if (e.scanLimit === null || e.scansUsed < e.scanLimit) return null;
  if (e.code === "free") return `You have used your ${FREE.scans} free scans. Choose a plan to keep scanning${e.bashCloud ? "" : ", or host your site on Bash Cloud to get 14 days free"}.`;
  if (e.code === "welcome") return `You have used the ${WELCOME.scans} scans of your Bash Cloud welcome. Choose a plan (${BASHCLOUD_DISCOUNT}% off for Bash Cloud customers) to keep scanning.`;
  return `Your ${e.name} plan's ${e.scanLimit} scans for this month are used. They renew on the 1st, or choose a bigger plan.`;
}

/** Why monitoring cannot be turned on for one more asset, or null if it can. */
export function monitorBlocked(e: Entitlement, monitoredNow: number, now = Date.now()): string | null {
  if (e.monitorLimit === null) return null;
  if (e.code === "free" && e.monitorEndsAt && Date.parse(e.monitorEndsAt) <= now) return "Your free day of monitoring has ended. Choose a plan to keep monitoring.";
  if (monitoredNow >= e.monitorLimit) return `Your ${e.name} plan monitors ${e.monitorLimit} ${e.monitorLimit === 1 ? "asset" : "assets"}. Pause one, or choose a bigger plan.`;
  return null;
}

/** Whether the background monitor may keep checking this account's assets. */
export function monitorActive(e: Entitlement, now = Date.now()): boolean {
  if (e.code !== "free") return true;
  return !!e.monitorEndsAt && Date.parse(e.monitorEndsAt) > now;
}

/** Price of a plan for this account, after any Bash Cloud discount. */
export function priceFor(p: PaidPlan, discount: number): { ngn: number; usd: number } {
  const cut = (n: number) => Math.round((n * (100 - discount)) / 100 * 100) / 100;
  return { ngn: Math.round(cut(p.ngn)), usd: cut(p.usd) };
}

/** What the browser is told about plans. */
export function planView(u: User, admin: boolean, monitoredNow: number) {
  const e = entitlement(u, admin);
  return {
    ...e,
    monitored: monitoredNow,
    welcome: { ...WELCOME, used: !!u.bashCloud },
    free: FREE,
    plans: PAID_PLANS.map((p) => ({ ...p, price: priceFor(p, e.discount) })),
    bashCloudDiscount: BASHCLOUD_DISCOUNT,
    payments: false,
    contact: (process.env.LUCENT_CONTACT_EMAIL ?? "").trim() || null,
  };
}

/**
 * Does Bash Cloud host this address? With LUCENT_BASHCLOUD_URL set, Bash Cloud
 * itself is asked (it answers only for its own apps and verified custom
 * domains). Without it, the site's last scan is used: Bash Cloud's shield
 * marks every response it serves.
 */
export async function hostedOnBashCloud(host: string, shieldedInScan: boolean): Promise<boolean> {
  const base = (process.env.LUCENT_BASHCLOUD_URL ?? "").trim().replace(/\/+$/, "");
  if (!base) return shieldedInScan;
  try {
    const r = await fetch(`${base}/api/public/hosted?host=${encodeURIComponent(host)}`, { signal: AbortSignal.timeout(5000) });
    if (!r.ok) return false;
    const d = (await r.json()) as { hosted?: boolean };
    return d.hosted === true;
  } catch {
    return false;
  }
}
