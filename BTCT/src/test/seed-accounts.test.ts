import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  DEFAULT_PRIMARY_ADMIN,
  PASSWORD_ALPHABET,
  PASSWORD_LENGTH,
  parseSeedNames,
  primaryAdminName,
  seedPasswordEnvName,
  envPasswordFor,
  generatePassword,
  DEFAULT_SEED_PASSWORD,
  planSeedAccounts,
  passwordFileLine,
} from '../../server/seed-accounts.mjs';

describe('parseSeedNames', () => {
  it('defaults to the five team names when SEED_USERS is unset', () => {
    expect(parseSeedNames(undefined).names).toEqual(['Warren', 'Ryan', 'Anthony', 'Jesse', 'Darren']);
  });
  it('an empty SEED_USERS seeds nobody', () => {
    expect(parseSeedNames('')).toEqual({ names: [], invalid: [] });
    expect(parseSeedNames(' , ').names).toEqual([]);
  });
  it('trims, drops blanks, keeps the first spelling of a repeat', () => {
    expect(parseSeedNames(' Alice ,,bob, ALICE ').names).toEqual(['Alice', 'bob']);
  });
  it('reports invalid names instead of seeding them', () => {
    const r = parseSeedNames('ok_name,a,has space,x');
    expect(r.names).toEqual(['ok_name']);
    expect(r.invalid).toEqual(['a', 'has space', 'x']);
  });
});

describe('primaryAdminName', () => {
  it('is Roberto unless ADMIN_USERNAME says otherwise', () => {
    expect(DEFAULT_PRIMARY_ADMIN).toBe('Roberto');
    expect(primaryAdminName({})).toBe('Roberto');
    expect(primaryAdminName({ ADMIN_USERNAME: '  ' })).toBe('Roberto');
    expect(primaryAdminName({ ADMIN_USERNAME: 'preview' })).toBe('preview');
  });
});

describe('env password lookup', () => {
  it('maps a name to SEED_PASSWORD_<UPPER>', () => {
    expect(seedPasswordEnvName('Warren')).toBe('SEED_PASSWORD_WARREN');
    expect(seedPasswordEnvName('j.doe-2')).toBe('SEED_PASSWORD_J_DOE_2');
  });
  it('reads the seed variable, or ADMIN_PASSWORD for the primary', () => {
    const env = { SEED_PASSWORD_RYAN: 'ryan-secret', ADMIN_PASSWORD: 'boss-secret', SEED_PASSWORD_ROBERTO: 'ignored' };
    expect(envPasswordFor('Ryan', env)).toEqual({ value: 'ryan-secret', source: 'SEED_PASSWORD_RYAN' });
    expect(envPasswordFor('Roberto', env, { primary: true })).toEqual({ value: 'boss-secret', source: 'ADMIN_PASSWORD' });
    expect(envPasswordFor('Warren', env)).toBeNull();
  });
  it('treats an empty or blank value as unset', () => {
    expect(envPasswordFor('Ryan', { SEED_PASSWORD_RYAN: '' })).toBeNull();
    expect(envPasswordFor('Ryan', { SEED_PASSWORD_RYAN: '   ' })).toBeNull();
    expect(envPasswordFor('x', { ADMIN_PASSWORD: '' }, { primary: true })).toBeNull();
  });
});

describe('generatePassword', () => {
  it('is long, from the unambiguous alphabet, and different each time', () => {
    const a = generatePassword(crypto.randomInt);
    const b = generatePassword(crypto.randomInt);
    expect(a).toHaveLength(PASSWORD_LENGTH);
    expect(PASSWORD_LENGTH).toBeGreaterThanOrEqual(16);
    expect([...a].every((c) => PASSWORD_ALPHABET.includes(c))).toBe(true);
    expect(PASSWORD_ALPHABET).not.toMatch(/[0O1lI]/);
    expect(a).not.toBe(b);
  });
  it('uses the random source it is given', () => {
    expect(generatePassword(() => 0, 4)).toBe(PASSWORD_ALPHABET[0]!.repeat(4));
  });
});

describe('planSeedAccounts', () => {
  const seeds = ['Warren', 'Ryan', 'Anthony', 'Jesse', 'Darren'];
  const actions = (p: ReturnType<typeof planSeedAccounts>) => p.map((s) => `${s.username}:${s.action}`);

  it('a fresh box creates all six, primary first', () => {
    const p = planSeedAccounts({ primary: 'Roberto', seeds, existing: [] });
    expect(actions(p)).toEqual([
      'Roberto:create', 'Warren:create', 'Ryan:create', 'Anthony:create', 'Jesse:create', 'Darren:create',
    ]);
    expect(p[0]!.primary).toBe(true);
    expect(p.slice(1).every((s) => !s.primary)).toBe(true);
  });

  it('existing accounts in any case are kept as they are, even non-admins', () => {
    const p = planSeedAccounts({
      primary: 'Roberto',
      seeds,
      existing: [
        { username: 'admin', isAdmin: true },
        { username: 'warren', isAdmin: false },
        { username: 'RYAN', isAdmin: true },
      ],
    });
    expect(actions(p)).toEqual([
      'Roberto:create', 'warren:keep', 'RYAN:keep', 'Anthony:create', 'Jesse:create', 'Darren:create',
    ]);
  });

  it('a second boot creates nothing', () => {
    const existing = ['Roberto', ...seeds].map((username) => ({ username, isAdmin: true }));
    expect(planSeedAccounts({ primary: 'Roberto', seeds, existing }).every((s) => s.action === 'keep')).toBe(true);
  });

  it('promotes only the primary, and only when the box has no admin', () => {
    const noAdmin = planSeedAccounts({
      primary: 'Roberto', seeds: ['Warren'],
      existing: [{ username: 'roberto', isAdmin: false }, { username: 'Warren', isAdmin: false }],
    });
    expect(actions(noAdmin)).toEqual(['roberto:promote', 'Warren:keep']);
    const someAdmin = planSeedAccounts({
      primary: 'Roberto', seeds: [],
      existing: [{ username: 'roberto', isAdmin: false }, { username: 'admin', isAdmin: true }],
    });
    expect(actions(someAdmin)).toEqual(['roberto:keep']);
  });

  it('folds a seed name that repeats the primary into it', () => {
    const p = planSeedAccounts({ primary: 'Warren', seeds: ['warren', 'Ryan'], existing: [] });
    expect(actions(p)).toEqual(['Warren:create', 'Ryan:create']);
  });
});

it('passwordFileLine is "username: password"', () => {
  expect(passwordFileLine('Warren', 'abc')).toBe('Warren: abc\n');
});

describe('DEFAULT_SEED_PASSWORD', () => {
  it('is the team password and passes the 8-character minimum', () => {
    expect(DEFAULT_SEED_PASSWORD).toBe('typst-best456');
    expect(DEFAULT_SEED_PASSWORD.length).toBeGreaterThanOrEqual(8);
  });
});
