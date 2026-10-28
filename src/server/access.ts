// Who may do what. The admin is the account whose email matches
// LUCENT_ADMIN_EMAIL. Only the admin can scan folders on this server, examine
// forensic artifacts here, or use the server's own GitHub token; everyone else
// scans repository URLs and websites they own.

import { store, type User } from "./store.ts";

export const ADMIN_EMAIL = (process.env.LUCENT_ADMIN_EMAIL ?? "").trim().toLowerCase();
/** Needed to create the admin account, so nobody else can claim the admin email first. */
export const ADMIN_PASSWORD = (process.env.LUCENT_ADMIN_PASSWORD ?? "").trim();

export function isAdminUser(user: User | undefined | null): boolean {
  return !!user && !!ADMIN_EMAIL && user.email === ADMIN_EMAIL;
}

export interface ScanOptions {
  admin: boolean;
  /** Token for private GitHub repositories (the server owner's only). */
  githubToken?: string;
}

export function scanOptionsFor(ownerId: string | undefined): ScanOptions {
  const admin = isAdminUser(ownerId ? store.user(ownerId) : undefined);
  const token = (process.env.LUCENT_GITHUB_TOKEN ?? "").trim();
  return admin ? { admin, githubToken: token || undefined } : { admin };
}
