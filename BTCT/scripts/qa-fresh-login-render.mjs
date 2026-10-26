// Fresh browser profile: log in, do NOT touch the workspace selector, open
// notes that have images and check every image renders and Assets is filled.
// Guards the boot path where loadWorkspaces() picks the default workspace
// (QA 2026-10-12: every note image read "image not found in assets").
//   docker run --rm --network host --ipc=host -v <dir with playwright@1.49.1>:/s \
//     -v <out>:/out -v <file holding the qa password>:/pw.txt:ro -w /s \
//     mcr.microsoft.com/playwright:v1.49.1-noble node qa-fresh-login-render.mjs chromium <url> <note title>...
import { chromium, firefox } from 'playwright';
import fs from 'node:fs';
const [name, url, ...titles] = process.argv.slice(2);
const PASS = fs.readFileSync('/pw.txt', 'utf8').trim();
const browser = await ({ chromium, firefox })[name].launch();
const page = await (await browser.newContext({ viewport: { width: 1400, height: 900 } })).newPage();
const res = { browser: name, pages: [] };
try {
  await page.goto(url);
  await page.getByLabel('Username').fill('qa'); await page.getByLabel('Password').fill(PASS);
  await page.getByRole('button', { name: 'Log in' }).click();
  await page.getByRole('button', { name: 'Export / Import' }).waitFor({ timeout: 60000 });
  res.persistedBefore = null;
  await page.waitForTimeout(2000);
  for (const t of titles) {
    const r = { title: t };
    try {
      await page.getByText(t, { exact: true }).first().click({ timeout: 15000 });
      await page.waitForFunction(() => {
        const imgs = [...document.querySelectorAll('.ProseMirror img[data-asset-id]')];
        return imgs.length > 0 && imgs.every((el) => el.src.startsWith('blob:') && el.naturalWidth > 0);
      }, null, { timeout: 30000 });
      r.images = await page.locator('.ProseMirror img[data-asset-id]').count();
    } catch (e) { r.error = String(e).split('\n')[0]; }
    r.notFound = await page.getByText(/image not found/i).count();
    res.pages.push(r);
  }
  res.activeWorkspaceId = JSON.parse(await page.evaluate(() => localStorage.getItem('btct.ui.v1')) || '{}').activeWorkspaceId;
  // Tools > Assets: count asset cards (img elements in the Assets panel).
  try {
    await page.getByText('Assets', { exact: true }).first().click({ timeout: 10000 });
    await page.waitForTimeout(4000);
    res.assetsEmptyText = await page.getByText(/No assets|no images|nothing here/i).count();
    res.assetsImgs = await page.locator('img').count();
  } catch (e) { res.assetsError = String(e).split('\n')[0]; }
  await page.screenshot({ path: `/out/fresh-${name}.png` });
} catch (e) { res.error = String(e).slice(0, 500); }
await browser.close();
console.log(JSON.stringify(res));
