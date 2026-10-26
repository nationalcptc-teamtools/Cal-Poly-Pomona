// HTTP benchmarks against a running throwaway server:
//   1. /healthz latency (sequential GETs)
//   2. POST /api/login latency (sequential, correct password, so the failure
//      throttle never kicks in; each one is a PBKDF2 verify)
//   3. Command log ingest: enable cmdlog as admin, take the ingest token from
//      POST /api/cmdlog/config, POST EVENTS events in batches of 200 (the
//      server cap), then read the count back from /api/cmdlog/export?format=count
// Run like relay.mjs (pinned Bun container, --network host). Env: BASE,
// BENCH_USER, BENCH_PASS, LOGINS (20), HEALTHZ (200), EVENTS (10000).
const BASE = (process.env.BASE || 'http://127.0.0.1:8098').replace(/\/$/, '');
const USER = process.env.BENCH_USER || 'Roberto';
const PASS = process.env.BENCH_PASS || 'typst-best456';
const LOGINS = Number(process.env.LOGINS || 20);
const HEALTHZ = Number(process.env.HEALTHZ || 200);
const EVENTS = Number(process.env.EVENTS || 10000);
const BATCH = 200;

const pct = (arr, p) => { const s = [...arr].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))]; };
const r2 = (x) => Math.round(x * 100) / 100;
const stats = (a) => ({ n: a.length, p50ms: r2(pct(a, 50)), p95ms: r2(pct(a, 95)), maxms: r2(Math.max(...a)), meanms: r2(a.reduce((x, y) => x + y, 0) / a.length) });

async function login() {
  const r = await fetch(`${BASE}/api/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: USER, password: PASS }),
  });
  if (!r.ok) throw new Error(`login ${r.status}`);
  return (await r.json()).token;
}

async function main() {
  const out = {};

  const hz = [];
  for (let i = 0; i < HEALTHZ; i++) {
    const t = performance.now();
    const r = await fetch(`${BASE}/healthz`); await r.arrayBuffer();
    if (r.status !== 200) throw new Error(`healthz ${r.status}`);
    hz.push(performance.now() - t);
  }
  out.healthz = stats(hz);

  const lg = [];
  let token;
  for (let i = 0; i < LOGINS; i++) {
    const t = performance.now();
    token = await login();
    lg.push(performance.now() - t);
  }
  out.login = { first_ms: r2(lg[0]), ...stats(lg) };

  // Five logins at once: shows whether PBKDF2 runs off the event loop.
  const tc = performance.now();
  await Promise.all(Array.from({ length: 5 }, () => login()));
  out.login5concurrent_wall_ms = r2(performance.now() - tc);

  if (EVENTS > 0) {
    const auth = { authorization: `Bearer ${token}`, 'content-type': 'application/json' };
    const cfg = await (await fetch(`${BASE}/api/cmdlog/config`, { method: 'POST', headers: auth, body: JSON.stringify({ enabled: true, workspaceId: 'bench-ws' }) })).json();
    const ingest = cfg.token;
    if (!ingest) throw new Error('no ingest token');
    const tools = ['nmap', 'ffuf', 'nxc', 'curl', 'hydra'];
    const now = Date.now();
    const per = [];
    let accepted = 0;
    const t0 = performance.now();
    for (let b = 0; b < EVENTS; b += BATCH) {
      const events = [];
      for (let i = b; i < Math.min(EVENTS, b + BATCH); i++) {
        const tool = tools[i % tools.length];
        events.push({
          id: `bench-${now}-${i}`, operator: 'bench', tool,
          command: `${tool} -sV -p- 10.0.${(i >> 8) & 255}.${i & 255} --some-flag value-${i}`,
          cwd: '/home/kali/engagement', host: 'kali', localUser: 'kali', shellPid: 4242,
          startedAt: now - (EVENTS - i) * 1000, exitCode: 0, durationMs: 1234,
        });
      }
      const t = performance.now();
      const r = await fetch(`${BASE}/api/cmdlog/events`, { method: 'POST', headers: { authorization: `Bearer ${ingest}`, 'content-type': 'application/json' }, body: JSON.stringify({ events, workspace: 'bench-ws' }) });
      const j = await r.json();
      if (!r.ok) throw new Error(`events ${r.status} ${JSON.stringify(j)}`);
      accepted += j.accepted;
      per.push(performance.now() - t);
    }
    const wall = performance.now() - t0;
    const tq = performance.now();
    const cnt = await (await fetch(`${BASE}/api/cmdlog/export?format=count&workspaceId=bench-ws`, { headers: auth })).text();
    const countMs = performance.now() - tq;
    const te = performance.now();
    const exp = await fetch(`${BASE}/api/cmdlog/export?format=json&workspaceId=bench-ws`, { headers: auth });
    const expBytes = (await exp.arrayBuffer()).byteLength;
    const exportMs = performance.now() - te;
    out.cmdlog = {
      events: EVENTS, batch: BATCH, accepted, wall_ms: r2(wall), events_per_sec: r2(EVENTS / (wall / 1000)),
      batch_post: stats(per), count_reply: cnt.slice(0, 200), count_ms: r2(countMs),
      export_json: { status: exp.status, bytes: expBytes, ms: r2(exportMs) },
    };
  }
  console.log(JSON.stringify(out, null, 2));
}

main().catch((e) => { console.error(e); process.exit(1); });
