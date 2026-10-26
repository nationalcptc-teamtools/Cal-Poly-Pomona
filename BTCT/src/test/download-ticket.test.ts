// @vitest-environment node
import { afterEach, describe, expect, it, vi } from 'vitest';
import { redeemTicket, signTicket, signToken, verifyToken } from '../../server/auth.mjs';

describe('one-time download tickets (server/auth.mjs)', () => {
  afterEach(() => { vi.useRealTimers(); });

  it('redeems once, for its own purpose only', () => {
    const t = signTicket('backup-archive', { uid: 1, name: 'btct-backup-20261015-120000.zip' });
    expect(redeemTicket('other', t)).toBeNull();
    const claims = redeemTicket('backup-archive', t);
    expect(claims?.uid).toBe(1);
    expect(claims?.name).toBe('btct-backup-20261015-120000.zip');
    expect(redeemTicket('backup-archive', t)).toBeNull();
  });

  it('is never a session token, and a session token is never a ticket', () => {
    const t = signTicket('backup-archive', { uid: 1, name: 'x' });
    expect(verifyToken(t)).toBeNull();
    const session = signToken({ uid: 1, admin: true });
    expect(redeemTicket('backup-archive', session)).toBeNull();
    expect(redeemTicket('backup-archive', `t1.${session}`)).toBeNull();
  });

  it('expires, and a tampered body fails the signature', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-10-15T12:00:00Z'));
    const t = signTicket('backup-archive', { uid: 1, name: 'x' }, 60);
    const [p, b, s] = t.split('.');
    const forged = JSON.parse(Buffer.from(b!, 'base64url').toString('utf8'));
    forged.uid = 2;
    expect(redeemTicket('backup-archive', `${p}.${Buffer.from(JSON.stringify(forged)).toString('base64url')}.${s}`)).toBeNull();
    vi.setSystemTime(new Date('2026-10-15T12:01:01Z'));
    expect(redeemTicket('backup-archive', t)).toBeNull();
  });
});
