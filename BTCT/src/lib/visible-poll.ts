/** Poll only while the browser tab is visible, without overlapping requests. */
export function pollWhileVisible(task: () => unknown | Promise<unknown>, interval: number): () => void {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let stopped = false;
  let running = false;
  const tick = async () => {
    if (stopped || document.hidden || running) return;
    running = true;
    try { await task(); }
    finally {
      running = false;
      if (!stopped && !document.hidden) timer = setTimeout(() => { void tick(); }, interval);
    }
  };
  const visibility = () => {
    clearTimeout(timer);
    if (!document.hidden) void tick();
  };
  document.addEventListener('visibilitychange', visibility);
  void tick();
  return () => { stopped = true; clearTimeout(timer); document.removeEventListener('visibilitychange', visibility); };
}
