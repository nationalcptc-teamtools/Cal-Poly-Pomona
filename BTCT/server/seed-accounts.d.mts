// Type surface of seed-accounts.mjs for the TypeScript side (tests + tsc).

export const DEFAULT_PRIMARY_ADMIN: string;
export const DEFAULT_SEED_USERS: string;
export const DEFAULT_SEED_PASSWORD: string;
export const SEED_USERNAME: RegExp;
export const PASSWORD_ALPHABET: string;
export const PASSWORD_LENGTH: number;

type Env = Record<string, string | undefined>;

export function parseSeedNames(raw: string | null | undefined, fallback?: string): { names: string[]; invalid: string[] };
export function primaryAdminName(env: Env): string;
export function seedPasswordEnvName(name: string): string;
export function envPasswordFor(name: string, env: Env, opts?: { primary?: boolean }): { value: string; source: string } | null;
export function generatePassword(randomInt: (max: number) => number, length?: number): string;

export interface SeedPlanEntry {
  username: string;
  primary: boolean;
  action: 'create' | 'promote' | 'keep';
}
export function planSeedAccounts(opts: {
  primary: string;
  seeds: string[];
  existing: Array<{ username: string; isAdmin: boolean }>;
}): SeedPlanEntry[];
export function passwordFileLine(username: string, password: string): string;
