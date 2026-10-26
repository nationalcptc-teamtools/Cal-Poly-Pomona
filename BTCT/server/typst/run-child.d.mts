export interface ChildResult {
  code: number | 'ENOENT';
  killed: boolean;
  aborted: boolean;
  signal: string | null;
  stderr: string;
}

export function runChild(
  cli: string,
  args: string[],
  cwd: string,
  options?: { timeoutMs?: number; signal?: AbortSignal | null },
): Promise<ChildResult>;
