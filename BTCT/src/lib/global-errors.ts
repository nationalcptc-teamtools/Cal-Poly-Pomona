let installed = false;

/** Log uncaught errors and rejected promises once; the default behaviour is left alone. */
export function installGlobalErrorLogging(): void {
  if (installed || typeof window === 'undefined') return;
  installed = true;
  window.addEventListener('error', (e) => {
    try { console.error('[global-error]', e.error ?? e.message); } catch { /* never throw */ }
  });
  window.addEventListener('unhandledrejection', (e) => {
    try { console.error('[unhandled-rejection]', e.reason); } catch { /* never throw */ }
  });
}
