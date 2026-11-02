/* 讓原本為 claude.ai 寫的頁面，改用自己的伺服器資料庫與登入。實作頁面用到的 db / user 介面。 */
(function () {
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
    es.onopen = () => Object.keys(subs).forEach(c => subs[c].size && refetch(c)); // 斷線重連後補抓
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
    box.style.cssText = 'margin-left:auto;margin-bottom:10px;display:flex;gap:6px;flex-wrap:wrap;align-items:center';
    const add = (t, fn) => { const b = document.createElement('button'); b.className = 'btn sm'; b.textContent = t; b.onclick = fn; box.appendChild(b); };
    if (me.role === 'admin') add('帳號管理', () => { location.href = '/admin'; });
    add('改密碼', () => { location.href = '/change-password'; });
    add('登出（' + me.display + '）', () => window.__logout());
    w.appendChild(box);
  });
  window.__logout = async () => { await api('POST', '/api/logout', {}); location.href = '/login'; };
})();
