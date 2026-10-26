// Relay benchmark: N y-websocket clients in one room, M updates, end-to-end
// propagation latency measured in this one process (one clock, no skew).
//
// Run inside the pinned Bun container with host networking so it reaches the
// throwaway server, with the client node_modules volume mounted (y-websocket,
// yjs come from the client deps):
//   docker run --rm --network host -v "$PWD":/app -w /app \
//     -v btct-harden-nm:/app/node_modules oven/bun:1.3.14 \
//     bun bench/relay.mjs
// Env: BASE (http://127.0.0.1:8098), BENCH_USER, BENCH_PASS, N (10),
//      M_PACED (1000), RATE (200 updates/s), M_BURST (2000), PAYLOAD (64 bytes).
//
// The URL and params mirror src/realtime/yjs-providers.ts: `${WS}/yjs` as the
// server URL, the room as the provider's room name, params { token, epoch? }.
// The epoch is only sent when GET /api/settings reports a restoreEpoch.
// disableBc is set so updates cannot short-cut through BroadcastChannel
// between clients in this process; every update goes through the relay.
import * as Y from 'yjs';
import { WebsocketProvider } from 'y-websocket';

const BASE = (process.env.BASE || 'http://127.0.0.1:8098').replace(/\/$/, '');
const WS = BASE.replace(/^http/, 'ws');
const N = Number(process.env.N || 10);
const M_PACED = Number(process.env.M_PACED || 1000);
const RATE = Number(process.env.RATE || 200);
const M_BURST = Number(process.env.M_BURST || 2000);
const PAYLOAD = Number(process.env.PAYLOAD || 64);
const USER = process.env.BENCH_USER || 'Roberto';
const PASS = process.env.BENCH_PASS || 'typst-best456';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const pct = (arr, p) => {
  if (!arr.length) return NaN;
  const s = [...arr].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))];
};
const r2 = (x) => Math.round(x * 100) / 100;

async function main() {
  const login = await fetch(`${BASE}/api/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: USER, password: PASS }),
  });
  if (!login.ok) throw new Error(`login ${login.status}`);
  const { token } = await login.json();
  let epoch = null;
  try {
    const s = await (await fetch(`${BASE}/api/settings`, { headers: { authorization: `Bearer ${token}` } })).json();
    epoch = s.restoreEpoch || null;
  } catch { /* no epoch */ }
  const params = epoch ? { token, epoch } : { token };
  const room = `bench-${Date.now()}`;

  const clients = [];
  const tConnect0 = performance.now();
  for (let i = 0; i < N; i++) {
    const doc = new Y.Doc();
    const provider = new WebsocketProvider(`${WS}/yjs`, room, doc, {
      params, connect: true, disableBc: true, WebSocketPolyfill: WebSocket,
    });
    const synced = new Promise((res) => {
      if (provider.synced) res();
      provider.on('sync', (ok) => { if (ok) res(); });
    });
    clients.push({ i, doc, provider, synced, map: doc.getMap('bench') });
  }
  await Promise.all(clients.map((c) => c.synced));
  const connectMs = performance.now() - tConnect0;

  const sentAt = new Map(); // key -> ms
  const lat = [];
  let received = 0;
  let waiters = [];
  for (const c of clients) {
    c.map.observe((ev, tr) => {
      if (tr.local) return;
      const now = performance.now();
      for (const k of ev.keysChanged) {
        const t = sentAt.get(k);
        if (t !== undefined) { lat.push(now - t); received++; }
      }
      if (waiters.length) {
        waiters = waiters.filter((w) => (received >= w.n ? (w.res(), false) : true));
      }
    });
  }
  const untilReceived = (n, timeoutMs) => new Promise((res) => {
    if (received >= n) return res(true);
    const w = { n, res: () => res(true) };
    waiters.push(w);
    setTimeout(() => res(false), timeoutMs);
  });
  const pad = 'x'.repeat(PAYLOAD);

  // Phase 1: paced writes, writer rotates across clients, N-1 receivers each.
  const interval = 1000 / RATE;
  const t1 = performance.now();
  for (let s = 0; s < M_PACED; s++) {
    const c = clients[s % N];
    const key = `p${s}`;
    sentAt.set(key, performance.now());
    c.map.set(key, pad);
    const next = t1 + (s + 1) * interval;
    const wait = next - performance.now();
    if (wait > 0) await sleep(wait);
  }
  const okPaced = await untilReceived(M_PACED * (N - 1), 30000);
  const pacedLat = lat.splice(0);
  const pacedReceived = received;

  // Phase 2: burst, every update written back to back from the event loop,
  // yielding every 50 so sockets drain. Throughput = deliveries / wall time.
  received = 0;
  const t2 = performance.now();
  for (let s = 0; s < M_BURST; s++) {
    const c = clients[s % N];
    const key = `b${s}`;
    sentAt.set(key, performance.now());
    c.map.set(key, pad);
    if (s % 50 === 49) await sleep(0);
  }
  const sendDone = performance.now();
  const okBurst = await untilReceived(M_BURST * (N - 1), 60000);
  const burstWall = performance.now() - t2;
  const burstLat = lat.splice(0);

  for (const c of clients) { c.provider.destroy(); c.doc.destroy(); }

  const out = {
    room, clients: N, payloadBytes: PAYLOAD, connectAllSyncedMs: r2(connectMs),
    paced: {
      updates: M_PACED, rateHz: RATE, expectedDeliveries: M_PACED * (N - 1),
      deliveries: pacedReceived, complete: okPaced,
      p50ms: r2(pct(pacedLat, 50)), p95ms: r2(pct(pacedLat, 95)), p99ms: r2(pct(pacedLat, 99)), maxms: r2(Math.max(...pacedLat)),
    },
    burst: {
      updates: M_BURST, expectedDeliveries: M_BURST * (N - 1), deliveries: burstLat.length, complete: okBurst,
      sendLoopMs: r2(sendDone - t2), wallMs: r2(burstWall),
      updatesPerSec: r2(M_BURST / (burstWall / 1000)),
      deliveriesPerSec: r2(burstLat.length / (burstWall / 1000)),
      p50ms: r2(pct(burstLat, 50)), p95ms: r2(pct(burstLat, 95)), maxms: r2(Math.max(...burstLat)),
    },
  };
  console.log(JSON.stringify(out, null, 2));
  await sleep(200);
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });
