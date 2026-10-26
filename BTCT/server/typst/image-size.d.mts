export function imageSize(bytes: Uint8Array): { width: number; height: number } | null;
export function looksLikeSvg(bytes: Uint8Array): boolean;
export function svgRefusal(bytes: Uint8Array, name: string): string | null;
