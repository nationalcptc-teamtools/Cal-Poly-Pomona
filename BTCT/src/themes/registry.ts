/** The operations interface uses solid surfaces and the browser's native CSS. */
export const UI_THEME = 'operations' as const;
export function applyUiTheme(): void {
  if (typeof document !== 'undefined') document.documentElement.setAttribute('data-ui-theme', UI_THEME);
}
