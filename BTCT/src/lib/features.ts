// Server-decided feature switches, as served under `features` by
// GET /api/settings. Env-driven on the server (ENABLE_TYPST), so a small box
// cannot be switched on from the UI. Anything but a literal `true` is off.

export interface Features {
  typst: boolean;
}

export const DEFAULT_FEATURES: Features = { typst: false };

export function resolveFeatures(payload: unknown): Features {
  if (!payload || typeof payload !== 'object') return { ...DEFAULT_FEATURES };
  const f = (payload as { features?: unknown }).features;
  if (!f || typeof f !== 'object') return { ...DEFAULT_FEATURES };
  return { typst: (f as { typst?: unknown }).typst === true };
}
