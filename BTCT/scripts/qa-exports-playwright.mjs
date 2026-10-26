// Browser round trip of the workspace archive through the real dialog.
//
// Exports a workspace from server A in Chromium and Firefox (the download
// must arrive, non-empty, on the first click), then imports the Chromium
// ZIP into server B through the dialog's file picker and opens a note to
// see its picture render. Run it in the Playwright image with the
// `playwright` package of the same version:
//
//   docker run --rm --network host -v <out>:/out -v <this dir>:/s -w /s \
//     mcr.microsoft.com/playwright:v1.49.1-noble sh -c \
//     'npm i --no-save --silent playwright@1.49.1 && node qa-exports-playwright.mjs'
//
// Env: A_URL, A_TOKEN, A_USER (JSON of the login response's user), B_URL,
// B_TOKEN, B_USER, WS (workspace id on A), OUT (default /out).
import { chromium, firefox } from 'playwright';
import fs from 'node:fs';

const env = (k, d = '') => process.env[k] ?? d;
const OUT = env('OUT', '/out');
const results = {};

async function open(browserType, url, token, user, workspaceId) {
  const browser = await browserType.launch();
  const context = await browser.newContext({ acceptDownloads: true });
  await context.addInitScript(([t, u, w]) => {
    localStorage.setItem('btct.auth.token', t);
    localStorage.setItem('btct.auth.user', u);
    if (w) localStorage.setItem('btct.ui.v1', JSON.stringify({ activeWorkspaceId: w }));
  }, [token, user, workspaceId]);
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  await page.goto(url);
  await page.getByRole('button', { name: 'Export / Import' }).waitFor({ timeout: 60_000 });
  return { browser, page, errors };
}

async function exportIn(name, browserType) {
  const { browser, page, errors } = await open(browserType, env('A_URL'), env('A_TOKEN'), env('A_USER'), env('WS'));
  try {
    await page.getByRole('button', { name: 'Export / Import' }).click();
    const started = Date.now();
    const [download] = await Promise.all([
      page.waitForEvent('download', { timeout: 180_000 }),
      page.getByRole('button', { name: /Full Workspace/ }).click(),
    ]);
    const file = `${OUT}/ui-${name}.zip`;
    await download.saveAs(file);
    const failure = await download.failure();
    await page.getByRole('status').filter({ hasText: /Exported \d+ notes/ }).waitFor({ timeout: 60_000 });
    const status = await page.getByRole('status').filter({ hasText: /Exported/ }).textContent();
    const [md] = await Promise.all([
      page.waitForEvent('download', { timeout: 60_000 }),
      page.getByRole('button', { name: /All Pages/ }).click(),
    ]);
    await md.saveAs(`${OUT}/ui-${name}-notes.zip`);
    results[name] = {
      ms: Date.now() - started, suggested: download.suggestedFilename(), bytes: fs.statSync(file).size, failure, status,
      markdown: { suggested: md.suggestedFilename(), bytes: fs.statSync(`${OUT}/ui-${name}-notes.zip`).size, failure: await md.failure() },
      errors,
    };
  } finally {
    await browser.close();
  }
}

async function importIn(name, browserType, zip) {
  const { browser, page, errors } = await open(browserType, env('B_URL'), env('B_TOKEN'), env('B_USER'), '');
  try {
    await page.getByRole('button', { name: 'Export / Import' }).click();
    await page.getByLabel(/Import as new/).check();
    const [chooser] = await Promise.all([
      page.waitForEvent('filechooser', { timeout: 30_000 }),
      page.getByRole('button', { name: 'Workspace ZIP' }).click(),
    ]);
    const started = Date.now();
    await chooser.setFiles(zip);
    const status = page.getByRole('status').filter({ hasText: /Imported as a new workspace|Import failed/ });
    await status.waitFor({ timeout: 300_000 });
    const text = await status.textContent();
    const ui = await page.evaluate(() => localStorage.getItem('btct.ui.v1'));
    const workspaceId = JSON.parse(ui ?? '{}').activeWorkspaceId ?? null;
    // Open the first note that has a picture and wait for the image to render.
    await page.keyboard.press('Escape');
    await page.mouse.click(5, 5);
    let picture = 'not checked';
    try {
      await page.getByText('Host 1', { exact: true }).first().click({ timeout: 15_000 });
      const img = page.locator('img[data-asset-id]').first();
      await img.waitFor({ timeout: 30_000 });
      await page.waitForFunction(() => {
        const el = document.querySelector('img[data-asset-id]');
        return el && el.src.startsWith('blob:') && el.naturalWidth > 0;
      }, null, { timeout: 30_000 });
      const missing = await page.getByText(/image not found/i).count();
      picture = missing ? `rendered, but ${missing} "image not found" placeholders` : 'rendered';
    } catch (e) {
      picture = `failed: ${String(e).split('\n')[0]}`;
    }
    results[`${name}-import`] = { ms: Date.now() - started, status: text, workspaceId, picture, errors };
    fs.writeFileSync(`${OUT}/import-report-ui.json`, JSON.stringify({ report: { workspaceId, sourceWorkspaceId: '' } }));
  } finally {
    await browser.close();
  }
}

await exportIn('chromium', chromium);
await exportIn('firefox', firefox);
await importIn('chromium', chromium, `${OUT}/ui-chromium.zip`);
fs.writeFileSync(`${OUT}/playwright.json`, JSON.stringify(results, null, 2));
console.log(JSON.stringify(results, null, 2));
