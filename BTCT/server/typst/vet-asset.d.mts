export interface AssetInventoryRow { id: string; workspaceId: string; kind: string; filename: string; mime: string; size: number }
export type VetResult = { ok: true; from: string; kind: 'image' | 'font'; name: string } | { ok: false; reason: string };
export function vetAssetRecord(record: unknown, row: AssetInventoryRow | null, workspaceId: string, assetsDir: string): VetResult;
