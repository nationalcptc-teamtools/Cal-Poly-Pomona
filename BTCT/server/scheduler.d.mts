// Type surface of scheduler.mjs for the TypeScript side (tests + tsc).

export interface JobStatus {
  name: string;
  running: boolean;
  runningSince: number | null;
  lastRunAt: number | null;
  lastSuccessAt: number | null;
  lastDurationMs: number | null;
  lastError: string | null;
  lastTrigger: string | null;
  nextRunAt: number | null;
  runs: number;
}

export interface JobOptions {
  name: string;
  intervalMs: () => number;
  enabled: () => boolean;
  run: (ctx: { trigger: string }) => Promise<unknown> | unknown;
  initialLastRunAt?: number | null;
  retryMs?: (() => number) | null;
  onStatus?: ((status: JobStatus) => void) | null;
  log?: ((line: string) => void) | null;
}

export interface Job {
  start(): void;
  stop(): void;
  reschedule(): void;
  trigger(reason?: string): Promise<{ ran: true; error: string | null; result: unknown } | { ran: false; reason: string }>;
  status(): JobStatus;
}

export function computeNextRun(
  lastRunAt: number | null,
  intervalMs: number,
  now?: number,
  opts?: { failed?: boolean; retryMs?: number },
): number;
export function createJob(opts: JobOptions): Job;
