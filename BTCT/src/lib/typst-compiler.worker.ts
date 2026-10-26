// ─────────────────────────────────────────────────────────────────────────
// Compiler Web Worker: owns the one typst.ts driver for the page and answers
// the client's requests one at a time, in order. Keeping the wasm here means
// a compile never blocks typing on the main thread.
// ─────────────────────────────────────────────────────────────────────────

import { createTypstDriver, dispatch } from './typst-compiler.driver';
import type { DriverRequest, DriverResponse } from './typst-compiler-types';

interface WorkerScope {
  onmessage: ((e: MessageEvent<DriverRequest>) => void) | null;
  postMessage(msg: DriverResponse): void;
}

const scope = self as unknown as WorkerScope;
const driver = createTypstDriver();

// Requests are handled strictly in arrival order: the driver carries
// per-compilation state, and the client relies on `setFonts` landing before
// the compile it was sent for.
let chain: Promise<void> = Promise.resolve();

scope.onmessage = (e) => {
  const req = e.data;
  chain = chain.then(async () => {
    try {
      const value = await dispatch(driver, req);
      scope.postMessage({ id: req.id, ok: true, value });
    } catch (err) {
      scope.postMessage({ id: req.id, ok: false, error: err instanceof Error ? err.message : String(err) });
    }
  });
};
