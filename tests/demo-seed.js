// 版面測試用的假資料（全部是虛構，不含任何真實客戶）。日期依「今天」產生，讓每個畫面都有內容。
const pad = n => String(n).padStart(2, '0');
const ymd = d => d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate());
const addDays = (d, n) => { const x = new Date(d); x.setDate(x.getDate() + n); return x; };
const ym = d => d.getFullYear() + '-' + pad(d.getMonth() + 1);

module.exports = function build(now = new Date()) {
  const today = ymd(now), period = ym(now), prev = ym(addDays(now, -31)), next = ym(addDays(now, 31));
  const clients = {}, services = {}, fees = {}, contracts = {}, tasks = {}, bills = {}, expenses = {}, todos = {}, contacts = {};
  const defs = [
    ['C901', '示範甲公司', '進行中', 'SEO', 120000, 5],
    ['C902', '示範乙診所', '進行中', 'GEO', 36000, -20],
    ['C903', '示範丙餐飲', '進行中', '內容行銷', 24000, 400],
    ['C904', '示範丁工作室', '結案', 'SEO', 0, -200],
  ];
  defs.forEach(([code, name, status, type, fee, endIn], i) => {
    clients[code] = { code, brand: name, fullName: name + '股份有限公司', taxId: '0000000' + i, status, industry: '測試', terms: '示範合約條款', needInvoice: i % 2 === 0, check: false, confirm: [] };
    contacts[code + '-p'] = { clientCode: code, name: '測試窗口' + (i + 1), primary: true, phone: '0900-000-00' + i };
    const sid = code + '-s1';
    services[sid] = { clientCode: code, type, mode: '經常性', cycle: '月繳', status: status === '結案' ? '結束' : '進行中', start: ymd(addDays(now, -120)), end: ymd(addDays(now, endIn)), articles: 12, reports: 1, contractNo: code + '-01' };
    if (fee) fees[sid] = { amount: fee, incl: true };
    contracts[code + '-01'] = { no: code + '-01', clientCode: code, status: status === '結案' ? '已結束' : '有效', start: ymd(addDays(now, -120)), end: ymd(addDays(now, endIn)), autoRenew: i === 0, check: false };
    if (status !== '結案') {
      [['週文章', 12, 170], ['月報告', 1, 700]].forEach(([kind, target, rate], k) => {
        const tid = `${code}-${period}-${k}`;
        tasks[tid] = { clientCode: code, kind, title: `${type}・${kind} ${period}`, period, target, done: k === 0 ? 3 : 0, rate, due: ymd(addDays(now, k === 0 ? -2 + i : 10)), assignee: i % 2 ? 'mio' : 'jimmy', sop: ['完成內容', '檢查', '記錄連結'], checked: [false, false, false], links: [], history: [], subN: 0, submitted: false, state: k === 0 && i === 0 ? '待驗收' : k === 0 && i === 1 ? '退回' : '待處理' };
      });
    }
    bills[`${code}-b1`] = { clientCode: code, period: prev, due: ymd(addDays(now, -25)), amount: fee || 10000, received: i === 0 ? fee : 0, receivedAt: i === 0 ? ymd(addDays(now, -20)) : null, incl: true, needInvoice: i % 2 === 0, invoiceNo: null, note: i === 1 ? '示範備註：客戶說月底才匯款' : null };
    bills[`${code}-b2`] = { clientCode: code, period, due: ymd(addDays(now, 7)), amount: i === 2 ? null : (fee || 10000), received: 0, incl: true, needInvoice: false, note: null };
    bills[`${code}-b3`] = { clientCode: code, period: next, due: ymd(addDays(now, 38)), amount: fee || 10000, received: 0, incl: true, needInvoice: false, note: null };
  });
  [['辦公室租金', '租金／水電', 15000], ['Google Ads', '廣告費', 880], ['外包寫手', '外包／稿費', 5000], ['記帳費', '會計／稅費', 2000]].forEach(([n, c, a], i) => {
    expenses['e' + i] = { date: ymd(addDays(now, -i * 3)), note: n, category: c, amount: a, paid: i !== 3, payee: '', clientCode: i === 2 ? 'C901' : '' };
  });
  ['確認示範合約', '整理示範資料夾', '回覆示範客戶'].forEach((t, i) => { todos['t' + i] = { title: t, detail: i === 0 ? '這是一段很長很長的說明文字，用來測試換行與省略是否正常，不會把版面撐開。' : null, done: false, owner: 'jimmy' }; });
  return { clients, services, fees, contracts, contacts, tasks, bills, expenses, todos };
};
