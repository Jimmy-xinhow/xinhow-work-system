#!/usr/bin/env node
/*
 * 版面／無障礙自動檢查：三種螢幕寬度 × 淺色/深色 × 管理者/員工，逐頁檢查
 *   - 橫向溢出（頁面比螢幕寬）
 *   - console / 頁面錯誤
 *   - 手機觸控目標過小（< 24px，WCAG 2.2 最低標準）
 *   - axe-core（WCAG 2 A/AA，serious 以上視為失敗）
 * 另外把每個畫面截圖存到 test-results/，改版前後可以用肉眼比對。
 *
 * 只能對「本機或測試用」資料庫執行：它會匯入一組虛構的示範資料。
 * 用法：
 *   npm i -D playwright axe-core && npx playwright install chromium
 *   BASE=http://localhost:3000 ADMIN_USER=jimmy ADMIN_PASS=… [STAFF_USER=mio STAFF_PASS=…] node tests/layout.test.js
 */
const fs = require('fs'), path = require('path');
let chromium; try { ({ chromium } = require('playwright')); } catch (e) { console.error('缺少 playwright：npm i -D playwright axe-core && npx playwright install chromium'); process.exit(2); }
let axeSrc = null; try { axeSrc = fs.readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8'); } catch (e) { console.warn('（沒有 axe-core，略過無障礙檢查）'); }

const BASE = (process.env.BASE || 'http://localhost:3000').replace(/\/$/, '');
if (!/^https?:\/\/(localhost|127\.0\.0\.1)/.test(BASE) && process.env.ALLOW_REMOTE !== '1') { console.error('只能對 localhost 執行（會匯入示範資料）。確定要對遠端執行請設 ALLOW_REMOTE=1'); process.exit(2); }
const USERS = [['admin', process.env.ADMIN_USER, process.env.ADMIN_PASS], ['staff', process.env.STAFF_USER, process.env.STAFF_PASS]].filter(u => u[1] && u[2]);
if (!USERS.length) { console.error('請設定 ADMIN_USER / ADMIN_PASS'); process.exit(2); }
const VIEWPORTS = [['phone', 360, 740, true], ['tablet', 768, 1024, true], ['desktop', 1280, 800, false]];
const VIEWS = { admin: ['dash', 'board?f=todo', 'clients', 'bills', 'bills?v=income', 'bills?v=expense', 'todos', 'notify', 'sop', 'audit'], staff: ['dash', 'board?f=todo', 'clients', 'todos', 'notify', 'sop'] };
const OUT = path.join(__dirname, '..', 'test-results'); fs.mkdirSync(OUT, { recursive: true });

(async () => {
  const browser = await chromium.launch();
  const fails = []; let checks = 0;
  // 準備資料（用管理者匯入，只新增不覆蓋）
  const admin = USERS.find(u => u[0] === 'admin');
  if (admin) {
    const r = await fetch(BASE + '/api/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name: admin[1], password: admin[2] }) });
    const cookie = (r.headers.get('set-cookie') || '').split(';')[0];
    const imp = await fetch(BASE + '/api/import?skip=1', { method: 'POST', headers: { 'content-type': 'application/json', cookie }, body: JSON.stringify(require('./demo-seed')()) });
    console.log('匯入示範資料：', imp.status);
  }
  for (const [role, user, pass] of USERS) for (const scheme of ['light', 'dark']) for (const [vp, w, h, touch] of VIEWPORTS) {
    const ctx = await browser.newContext({ viewport: { width: w, height: h }, hasTouch: touch, isMobile: touch, colorScheme: scheme });
    const page = await ctx.newPage(); await page.route(/fonts\.g/, r => r.abort());
    const errs = []; page.on('pageerror', e => errs.push(e.message)); page.on('console', m => { if (m.type() === 'error' && !/Failed to load resource/.test(m.text())) errs.push(m.text()); });
    page.on('requestfailed', r => { if (!/fonts\.g|favicon/.test(r.url())) errs.push('請求失敗 ' + r.url()); });
    page.on('response', r => { if (r.status() >= 400 && !/favicon/.test(r.url())) errs.push(r.status() + ' ' + r.url()); });
    await page.goto(BASE + '/login');
    await page.evaluate(async ([n, p]) => { await fetch('/api/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name: n, password: p }) }); }, [user, pass]);
    for (const v of VIEWS[role]) {
      const tag = `${role}/${scheme}/${vp}/${v}`;
      await page.goto(BASE + '/#/' + v); await page.reload(); await page.waitForTimeout(900);
      const m = await page.evaluate(() => {
        const W = innerWidth, bad = [], small = [];
        const scrolls = e => { for (let a = e.parentElement; a && a !== document.body; a = a.parentElement) { const o = getComputedStyle(a).overflowX; if (o === 'auto' || o === 'scroll' || o === 'hidden') return true; } return false; };
        document.querySelectorAll('body *').forEach(e => {
          const cs = getComputedStyle(e); if (cs.display === 'none' || cs.visibility === 'hidden') return;
          const r = e.getBoundingClientRect(); if (!r.width) return;
          if ((r.right > W + 1 || r.left < -1) && !scrolls(e) && cs.position !== 'fixed') bad.push((e.tagName + '.' + (e.className.baseVal !== undefined ? e.className.baseVal : e.className)).slice(0, 40));
          if (['BUTTON', 'A', 'INPUT', 'SELECT'].includes(e.tagName) && e.type !== 'hidden' && (r.height < 24 || r.width < 24) && r.height > 0) small.push(e.tagName + '.' + String(e.className).slice(0, 30) + ' ' + Math.round(r.width) + 'x' + Math.round(r.height));
        });
        return { sw: document.documentElement.scrollWidth, W, bad: [...new Set(bad)].slice(0, 4), small: [...new Set(small)].slice(0, 4) };
      });
      checks++;
      if (m.sw > m.W + 1 || m.bad.length) fails.push(`${tag} 橫向溢出 sw=${m.sw}/${m.W} ${m.bad.join(', ')}`);
      if (touch && m.small.length) fails.push(`${tag} 觸控目標過小 ${m.small.join(' | ')}`);
      if (axeSrc) {
        await page.evaluate(axeSrc);
        const r = await page.evaluate(async () => (await axe.run(document, { runOnly: ['wcag2a', 'wcag2aa'], resultTypes: ['violations'] })).violations.map(x => ({ id: x.id, impact: x.impact, n: x.nodes.length, t: x.nodes[0].target[0] })));
        r.filter(x => ['serious', 'critical'].includes(x.impact)).forEach(x => fails.push(`${tag} axe:${x.id}(${x.n}) 例：${x.t}`));
      }
      if (v.startsWith('board')) { // 列表內快速回報：展開、axe、收合
        for (let i = 0; i < 4 && !(await page.$('[data-act=qopen]')); i++) { const h = await page.$$('.grp-head[aria-expanded=false]'); if (!h.length) break; await h[0].click(); await page.waitForTimeout(250); }
        const qb = await page.$('[data-act=qopen]');
        if (!qb && role === 'admin') fails.push(`${tag} 找不到可回報的任務（測試資料問題）`);
        if (qb) {
          await qb.click(); await page.waitForTimeout(300);
          if (!(await page.$('#qr_url'))) fails.push(`${tag} 快速回報沒有展開`);
          if (axeSrc) { const r = await page.evaluate(async () => (await axe.run(document, { runOnly: ['wcag2a', 'wcag2aa'], resultTypes: ['violations'] })).violations.map(x => ({ id: x.id, impact: x.impact, t: x.nodes[0].target[0] }))); r.filter(x => ['serious', 'critical'].includes(x.impact)).forEach(x => fails.push(`${tag} 快速回報 axe:${x.id} 例：${x.t}`)); }
          await page.screenshot({ path: path.join(OUT, tag.replace(/[/?=]/g, '_') + '_report.png') });
          const close = await page.$('[data-act=qopen][aria-expanded=true]'); if (close) await close.click();
        }
      }
      if (v === 'dash') { // 全域搜尋：開啟、輸入、版面、axe
        await page.keyboard.press('Control+k'); await page.keyboard.type('示範'); await page.waitForTimeout(250);
        if (!(await page.evaluate(() => !!document.querySelector('#cmdk .ck-i')))) fails.push(`${tag} 全域搜尋沒有結果`);
        if (axeSrc) { const r = await page.evaluate(async () => (await axe.run(document, { runOnly: ['wcag2a', 'wcag2aa'], resultTypes: ['violations'] })).violations.map(x => ({ id: x.id, impact: x.impact, t: x.nodes[0].target[0] }))); r.filter(x => ['serious', 'critical'].includes(x.impact)).forEach(x => fails.push(`${tag} 搜尋面板 axe:${x.id} 例：${x.t}`)); }
        await page.screenshot({ path: path.join(OUT, tag.replace(/[/?=]/g, '_') + '_search.png') });
        await page.keyboard.press('Escape');
      }
      await page.screenshot({ path: path.join(OUT, tag.replace(/[/?=]/g, '_') + '.png'), fullPage: true });
    }
    if (errs.length) fails.push(`${role}/${scheme}/${vp} 主控台錯誤：${[...new Set(errs)].slice(0, 3).join(' | ')}`);
    await ctx.close();
  }
  await browser.close();
  console.log(`檢查 ${checks} 個畫面，截圖在 test-results/`);
  if (fails.length) { console.error('\n失敗 ' + fails.length + ' 項：\n- ' + fails.join('\n- ')); process.exit(1); }
  console.log('全部通過');
})();
