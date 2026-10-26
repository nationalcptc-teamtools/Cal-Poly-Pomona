// How long the Word converter may run, from DOCX_CONVERT_TIMEOUT_S.
//
// Unset, empty, 0 or anything that is not a positive finite number means no
// cap: the converter runs until it finishes and is given no budget, so it
// never drops a layout pass to save time. A 119-page report needs about four
// minutes that way on one core, and the old fixed 120 s kill failed it
// outright. A positive number brings a cap back, and the converter is told
// 15 s less than the cap so it can decline a second conversion rather than be
// killed halfway through one (reading the PDF, both text checks and writing
// the file sit outside the pdf2docx pass it measures).

const BUDGET_MARGIN_S = 15;

export function convertLimit(value) {
  const seconds = Number(String(value ?? '').trim());
  if (!Number.isFinite(seconds) || seconds <= 0) return { timeoutMs: 0, budgetSeconds: null };
  return { timeoutMs: Math.round(seconds * 1000), budgetSeconds: Math.max(1, Math.round(seconds - BUDGET_MARGIN_S)) };
}
