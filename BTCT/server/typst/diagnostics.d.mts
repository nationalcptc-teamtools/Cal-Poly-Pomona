export interface Diagnostic { severity: 'error' | 'warning'; message: string; file: string | null; line: number | null; col: number | null }
export interface ChildResult { code?: number | string | null; signal?: string | null; killed?: boolean; stderr?: string }
export function parseDiagnostics(stderr: string, root: string): Diagnostic[];
export function scrubPaths(text: string, root: string): string;
export function childFailureMessage(result: ChildResult | null, tool: string): string | null;
export function truncate(text: string, max: number): string;
/**
 * `resultMessage`: what the bake child wrote, `''` for a result file with no
 * message, `null`/absent for no result file at all.
 */
export interface BakeResult extends ChildResult {
  resultOk?: boolean;
  resultMessage?: string | null;
  outputExists?: boolean;
}
export function bakeFailureMessage(result: BakeResult | null, name: string): string;
export function docxFailureMessage(result: BakeResult | null): string;
