// ─────────────────────────────────────────────────────────────────────────
// Default accounts created on boot. Pure logic only (no database, no files),
// so the tests can drive it; server/index.mjs does the I/O.
//
// Every BTCT gets a primary admin (ADMIN_USERNAME, default Roberto) plus the
// names in SEED_USERS (default Warren,Ryan,Anthony,Jesse,Darren), all admins.
// An account is created only when no account with that name exists in any
// case. An existing account is never changed, with one exception kept from
// the old bootstrap: when the box has no admin at all and the primary name
// exists, that account is promoted so the box always has a way in.
// ─────────────────────────────────────────────────────────────────────────

export const DEFAULT_PRIMARY_ADMIN = 'Roberto';
export const DEFAULT_SEED_USERS = 'Warren,Ryan,Anthony,Jesse,Darren';
export const SEED_USERNAME = /^[a-zA-Z0-9_.-]{3,32}$/;

// The team's shared password for every seeded account, used when no
// ADMIN_PASSWORD / SEED_PASSWORD_<NAME> is set. Hardcoded on purpose so a
// fresh competition box comes up with logins everyone already knows.
export const DEFAULT_SEED_PASSWORD = 'typst-best456';

// No 0/O, 1/l/I: the password is read off a log or a text file and typed.
export const PASSWORD_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
export const PASSWORD_LENGTH = 20;

/** An env value, or null when it is unset or only whitespace. */
function envValue(env, key) {
  const v = env[key];
  return typeof v === 'string' && v.trim() !== '' ? v : null;
}

/**
 * The extra names to seed. `raw` is SEED_USERS: undefined means the default
 * list, an empty string means none. Names are trimmed, blanks dropped, and
 * a repeat (any case) keeps its first spelling. Invalid names come back in
 * `invalid` so the caller can warn about them.
 */
export function parseSeedNames(raw, fallback = DEFAULT_SEED_USERS) {
  const source = raw === undefined || raw === null ? fallback : String(raw);
  const names = [];
  const invalid = [];
  const seen = new Set();
  for (const part of source.split(',')) {
    const name = part.trim();
    if (!name) continue;
    if (!SEED_USERNAME.test(name)) { invalid.push(name); continue; }
    const key = name.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    names.push(name);
  }
  return { names, invalid };
}

/** The primary admin's name: ADMIN_USERNAME when set, else Roberto. */
export function primaryAdminName(env) {
  const v = envValue(env, 'ADMIN_USERNAME');
  return v ? v.trim() : DEFAULT_PRIMARY_ADMIN;
}

/** SEED_PASSWORD_<NAME>, upper-cased, with anything but A-Z 0-9 as `_`. */
export function seedPasswordEnvName(name) {
  return `SEED_PASSWORD_${String(name).toUpperCase().replace(/[^A-Z0-9]/g, '_')}`;
}

/**
 * The password an operator set for this account, as `{ value, source }`
 * (source is the env variable's name), or null when none is set. The primary
 * admin reads ADMIN_PASSWORD; a seeded account reads SEED_PASSWORD_<NAME>.
 */
export function envPasswordFor(name, env, { primary = false } = {}) {
  const key = primary ? 'ADMIN_PASSWORD' : seedPasswordEnvName(name);
  const value = envValue(env, key);
  return value === null ? null : { value, source: key };
}

/**
 * A random password from PASSWORD_ALPHABET. `randomInt(max)` must return an
 * unbiased integer in [0, max); the server passes crypto.randomInt.
 */
export function generatePassword(randomInt, length = PASSWORD_LENGTH) {
  let out = '';
  for (let i = 0; i < length; i++) out += PASSWORD_ALPHABET[randomInt(PASSWORD_ALPHABET.length)];
  return out;
}

/**
 * What boot should do for each wanted account, primary first.
 *   existing: the current accounts, `{ username, isAdmin }`.
 * Returns `[{ username, primary, action }]` where action is 'create',
 * 'promote' (primary only, and only when no account is an admin) or 'keep'.
 * A seed name equal to the primary name (any case) is folded into it.
 */
export function planSeedAccounts({ primary, seeds, existing }) {
  const byName = new Map();
  for (const u of existing) byName.set(String(u.username).toLowerCase(), u);
  const anyAdmin = existing.some((u) => u.isAdmin);
  const plan = [];
  const seen = new Set();
  const add = (username, isPrimary) => {
    const key = username.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    const found = byName.get(key);
    let action = 'keep';
    if (!found) action = 'create';
    else if (isPrimary && !found.isAdmin && !anyAdmin) action = 'promote';
    plan.push({ username: found ? found.username : username, primary: isPrimary, action });
  };
  add(primary, true);
  for (const s of seeds) add(s, false);
  return plan;
}

/** One line of the initial-passwords file. */
export function passwordFileLine(username, password) {
  return `${username}: ${password}\n`;
}
