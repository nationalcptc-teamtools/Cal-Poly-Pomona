export const DEFAULT_MAX_TOTAL_MP: number;
export const MAX_TOTAL_MP_RANGE: [number, number];
export const MAX_TOTAL_MP: number;
export function parseMaxTotalMegapixels(raw: string | undefined | null): number;
export function createPixelBudget(maxMegapixels?: number): { add(dims: { width: number; height: number } | null | undefined): string | null; megapixels(): number };
