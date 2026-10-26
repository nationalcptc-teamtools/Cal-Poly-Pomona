// Type surface of auth.mjs for the TypeScript side (tests + tsc).
// Keep in sync with the .mjs; the runtime has no build step.

export function hashPassword(password: string): Promise<{ salt: string; hash: string; iter: number }>;
export function verifyPassword(password: string, salt: string, expectedHash: string, iter: number): Promise<boolean>;
export function signToken(payload: Record<string, unknown>): string;
export function verifyToken(token: unknown): (Record<string, unknown> & { exp: number }) | null;
export function signTicket(purpose: string, claims: Record<string, unknown>, ttlSeconds?: number): string;
export function redeemTicket(purpose: string, ticket: unknown): (Record<string, unknown> & { exp: number; n: string }) | null;
