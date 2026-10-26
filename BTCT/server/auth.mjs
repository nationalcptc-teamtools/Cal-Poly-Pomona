import crypto from 'node:crypto';

// PBKDF2 parameters. 200k iterations of SHA-256 is OWASP-recommended for 2024+.
const PBKDF2_ITER = 200_000;
const PBKDF2_KEYLEN = 32;
const PBKDF2_DIGEST = 'sha256';

const AUTH_SECRET =
  process.env.AUTH_SECRET ||
  (() => {
    console.warn(
      '[auth] AUTH_SECRET not set; using a random ephemeral secret. ' +
        'Tokens will be invalidated on restart. Set AUTH_SECRET in production.',
    );
    return crypto.randomBytes(32).toString('hex');
  })();

const TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days

function b64url(buf) {
  return Buffer.from(buf)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64');
}

// PBKDF2 on the libuv threadpool, not the event loop: 200k iterations is
// ~100ms of CPU, and this process also runs the Yjs relay, so a synchronous
// hash freezes every connected editor for the duration.
function pbkdf2Async(password, salt, iter) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, iter, PBKDF2_KEYLEN, PBKDF2_DIGEST, (err, key) =>
      err ? reject(err) : resolve(key));
  });
}

export async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = await pbkdf2Async(password, salt, PBKDF2_ITER);
  return {
    salt: salt.toString('hex'),
    hash: hash.toString('hex'),
    iter: PBKDF2_ITER,
  };
}

export async function verifyPassword(password, salt, expectedHash, iter) {
  const hash = await pbkdf2Async(password, Buffer.from(salt, 'hex'), iter);
  const a = Buffer.from(expectedHash, 'hex');
  if (hash.length !== a.length) return false;
  return crypto.timingSafeEqual(hash, a);
}

export function signToken(payload) {
  const body = { ...payload, exp: Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS };
  const b = b64url(JSON.stringify(body));
  const sig = b64url(
    crypto.createHmac('sha256', AUTH_SECRET).update(b).digest(),
  );
  return `${b}.${sig}`;
}

export function verifyToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [b, sig] = parts;
  const expected = b64url(
    crypto.createHmac('sha256', AUTH_SECRET).update(b).digest(),
  );
  // constant-time compare
  const a = Buffer.from(sig);
  const e = Buffer.from(expected);
  if (a.length !== e.length || !crypto.timingSafeEqual(a, e)) return null;
  let payload;
  try {
    payload = JSON.parse(b64urlDecode(b).toString('utf8'));
  } catch {
    return null;
  }
  if (
    !payload ||
    typeof payload !== 'object' ||
    typeof payload.exp !== 'number' ||
    payload.exp < Math.floor(Date.now() / 1000)
  ) {
    return null;
  }
  return payload;
}

// ── One-time download tickets ──────────────────────────────────────────
//
// A browser that cannot send the Authorization header (a plain link the
// browser downloads itself) gets a ticket in the URL instead of the session
// token. A ticket is HMAC-signed with a key derived for its purpose, so it
// never verifies as a session token (three dot-separated parts, a different
// key) and a session token never verifies as a ticket. It names what it
// opens, expires after `ttlSeconds` and is accepted once: its nonce is
// remembered until it expires.

const TICKET_PREFIX = 't1';
const TICKET_MAX_TTL_SECONDS = 300;
const TICKET_MAX_OUTSTANDING = 10_000;
const redeemedTickets = new Map(); // nonce -> exp (seconds)

function ticketKey(purpose) {
  return crypto.createHmac('sha256', AUTH_SECRET).update(`btct-ticket:${purpose}`).digest();
}

function pruneRedeemedTickets(now) {
  for (const [nonce, exp] of redeemedTickets) if (exp < now) redeemedTickets.delete(nonce);
}

/** A signed ticket for `purpose` carrying `claims`, valid for `ttlSeconds` (at most 300). */
export function signTicket(purpose, claims, ttlSeconds = 60) {
  const ttl = Math.max(1, Math.min(TICKET_MAX_TTL_SECONDS, Math.floor(ttlSeconds)));
  const body = { ...claims, n: b64url(crypto.randomBytes(12)), exp: Math.floor(Date.now() / 1000) + ttl };
  const b = b64url(JSON.stringify(body));
  const sig = b64url(crypto.createHmac('sha256', ticketKey(purpose)).update(`${TICKET_PREFIX}.${b}`).digest());
  return `${TICKET_PREFIX}.${b}.${sig}`;
}

/**
 * The claims of a valid, unexpired, not yet redeemed ticket for `purpose`,
 * marking it redeemed; null for anything else.
 */
export function redeemTicket(purpose, ticket) {
  if (typeof ticket !== 'string' || ticket.length > 2048) return null;
  const parts = ticket.split('.');
  if (parts.length !== 3 || parts[0] !== TICKET_PREFIX) return null;
  const expected = b64url(crypto.createHmac('sha256', ticketKey(purpose)).update(`${parts[0]}.${parts[1]}`).digest());
  const a = Buffer.from(parts[2]);
  const e = Buffer.from(expected);
  if (a.length !== e.length || !crypto.timingSafeEqual(a, e)) return null;
  let payload;
  try { payload = JSON.parse(b64urlDecode(parts[1]).toString('utf8')); } catch { return null; }
  const now = Math.floor(Date.now() / 1000);
  if (!payload || typeof payload !== 'object' || typeof payload.exp !== 'number' || payload.exp < now) return null;
  if (typeof payload.n !== 'string' || !payload.n) return null;
  pruneRedeemedTickets(now);
  if (redeemedTickets.has(payload.n)) return null;
  // A flood of unredeemed-then-redeemed tickets cannot grow this past a cap:
  // every entry expires within TICKET_MAX_TTL_SECONDS anyway.
  if (redeemedTickets.size >= TICKET_MAX_OUTSTANDING) return null;
  redeemedTickets.set(payload.n, payload.exp);
  return payload;
}
