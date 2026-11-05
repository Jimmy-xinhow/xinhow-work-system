/* 讓原本為 claude.ai 寫的頁面，改用自己的伺服器資料庫與登入。實作頁面用到的 db / user 介面。 */
(function () {
  /* 外觀：跟隨系統（預設）／明亮／暗色，存在這台瀏覽器；在頁面畫出來之前就套用，避免閃一下 */
  const THEMES = [[null, '跟隨系統'], ['light', '明亮'], ['dark', '暗色']];
  const getTheme = () => { try { const v = localStorage.getItem('xh-theme'); return v === 'light' || v === 'dark' ? v : null; } catch (e) { return null; } };
  const applyTheme = v => { const r = document.documentElement; if (v) r.setAttribute('data-theme', v); else r.removeAttribute('data-theme'); };
  applyTheme(getTheme());
  const toLogin = () => { location.href = '/login'; return new Promise(() => {}); };
  // 先取得登入者與帳號清單，頁面啟動前 window.__me / window.__users 就已就緒
  const meP = fetch('/api/me', { credentials: 'same-origin' }).then(async r => {
    if (r.status === 401) return toLogin();
    const me = await r.json();
    if (me.mustChange) { location.href = '/change-password'; return new Promise(() => {}); }
    window.__me = me;
    try { const u = await fetch('/api/users/public', { credentials: 'same-origin' }); if (u.ok) window.__users = await u.json(); } catch (e) {}
    return me;
  });
  const J = { 'Content-Type': 'application/json' };
  async function api(method, url, body) {
    const r = await fetch(url, { method, headers: body !== undefined ? J : undefined, body: body !== undefined ? JSON.stringify(body) : undefined, credentials: 'same-origin' });
    if (r.status === 401) { location.href = '/login'; return new Promise(() => {}); }
    if (!r.ok) { let m = r.statusText; try { m = (await r.json()).error || m; } catch (e) {} throw new Error(m); }
    return r.json();
  }
  const subs = {}; // coll -> Set of fn
  const listeners = {};
  async function refetch(coll) {
    try {
      const rows = await api('GET', '/api/c/' + encodeURIComponent(coll));
      const snap = { docs: rows.map(r => ({ id: r.id, data: () => r.data })) };
      (subs[coll] || []).forEach(s => s.ok(snap));
    } catch (e) { (subs[coll] || []).forEach(s => s.err && s.err(e)); }
  }
  let es = null;
  function stream() {
    if (es) return;
    es = new EventSource('/api/stream');
    es.onmessage = ev => { try { const c = JSON.parse(ev.data).coll; if (subs[c] && subs[c].size) { clearTimeout(listeners[c]); listeners[c] = setTimeout(() => refetch(c), 80); } } catch (e) {} };
    es.onopen = () => { window.dispatchEvent(new Event('xh-online')); Object.keys(subs).forEach(c => subs[c].size && refetch(c)); }; // 斷線重連後補抓
    es.onerror = () => window.dispatchEvent(new Event('xh-offline'));
  }
  const rnd = () => Array.from(crypto.getRandomValues(new Uint8Array(10))).map(b => b.toString(16).padStart(2, '0')).join('');
  function collection(c) {
    const enc = encodeURIComponent(c);
    return {
      doc(id) {
        const did = id || rnd(), p = '/api/c/' + enc + '/' + encodeURIComponent(did);
        return {
          id: did,
          set: async d => { await api('PUT', p, d); await refetch(c); },
          update: async d => { await api('PATCH', p, d); await refetch(c); },
          delete: async () => { await api('DELETE', p); await refetch(c); }
        };
      },
      add: async d => { const r = await api('POST', '/api/c/' + enc, d); await refetch(c); return { id: r.id }; },
      onSnapshot(ok, err) {
        const s = { ok, err }; (subs[c] ||= new Set()).add(s); stream(); refetch(c);
        return () => subs[c].delete(s);
      }
    };
  }
  window.claude = {
    async use(name) {
      const me = await meP;
      if (name === 'db') return { collection };
      if (name === 'user') return { canEdit: async () => me.role === 'admin', can: async () => true, isOwner: async () => me.role === 'admin', name: me.name };
      return null;
    }
  };
  document.addEventListener('DOMContentLoaded', async () => {
    const me = await meP, w = document.querySelector('.top .wrap');
    if (!w) return;
    const box = document.createElement('div');
    box.className = 'acct';
    box.style.cssText = 'margin-left:auto;margin-bottom:10px;display:flex;gap:6px;align-items:center';
    const menu = document.createElement('div'); menu.className = 'acct-menu';
    const tg = document.createElement('button'); tg.className = 'btn sm acct-toggle'; tg.textContent = me.display + ' ▾';
    tg.onclick = e => { e.stopPropagation(); box.classList.toggle('open'); };
    document.addEventListener('click', () => box.classList.remove('open'));
    box.appendChild(tg); box.appendChild(menu);
    const add = (t, fn) => { const b = document.createElement('button'); b.className = 'btn sm'; b.textContent = t; b.onclick = fn; menu.appendChild(b); };
    const th = document.createElement('button'); th.className = 'btn sm'; th.type = 'button';
    const label = () => { const c = getTheme(); th.textContent = '外觀：' + THEMES.find(x => x[0] === c)[1]; th.setAttribute('aria-label', '切換外觀，目前' + THEMES.find(x => x[0] === c)[1]); };
    th.onclick = e => { e.stopPropagation(); const i = THEMES.findIndex(x => x[0] === getTheme()); const n = THEMES[(i + 1) % THEMES.length][0]; try { if (n) localStorage.setItem('xh-theme', n); else localStorage.removeItem('xh-theme'); } catch (er) {} applyTheme(n); label(); };
    label(); menu.appendChild(th);
    if (me.role === 'admin') add('帳號管理', () => { location.href = '/admin'; });
    add('改密碼', () => { location.href = '/change-password'; });
    add('登出（' + me.display + '）', () => window.__logout());
    w.appendChild(box);
  });
  window.__logout = async () => { await api('POST', '/api/logout', {}); location.href = '/login'; };
})();
