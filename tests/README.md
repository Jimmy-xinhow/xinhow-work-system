# 版面／無障礙自動檢查

改版後跑一次，確認 3 種螢幕寬度 × 淺色/深色 × 管理者/員工的每個畫面沒有：橫向溢出、主控台錯誤、過小的觸控目標、axe-core 嚴重以上的無障礙問題。截圖輸出到 `test-results/`（已加入 .gitignore）。

資料全為虛構（`demo-seed.js`），**請只對本機或測試用資料庫執行**；腳本預設只允許 localhost。

```
npm i --no-save playwright axe-core && npx playwright install chromium
BASE=http://localhost:3000 ADMIN_USER=… ADMIN_PASS=… STAFF_USER=… STAFF_PASS=… npm run test:layout
```
