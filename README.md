# 星昊科技工作管理系統（Railway 版）

Node.js + Postgres。兩個帳號登入（管理者／員工）。費用、帳款、通知管道、週期任務設定只有管理者讀得到；驗收只有管理者寫得進去（伺服器端強制）。

## 環境變數
- `DATABASE_URL`：資料庫連線（Railway 用 `${{Postgres.DATABASE_URL}}`）
- `SESSION_SECRET`：至少 24 字元的隨機字串
- `ADMIN_PASSWORD`、`STAFF_PASSWORD`：兩個帳號的密碼；`ADMIN_NAME`（預設 jimmy）、`STAFF_NAME`（預設 mio）

## 匯入初始資料
客戶資料不放在程式碼儲存庫裡。登入管理者帳號後開啟 `/import`，選擇 seed.json（或備份檔）上傳即可。

## 備份與還原
管理者登入後開啟 `/api/export` 會下載全部資料；要還原就用 `/import` 上傳同一個檔。建議每月備份一次。

## 注意
- 只能跑 1 個實例（即時更新用記憶體廣播）。
- 沒有忘記密碼功能：到 Railway Variables 改密碼，服務會自動重啟。
- 登入有效 30 天；連續輸錯 10 次鎖 10 分鐘。
- 網頁在 `public/index.html`，shim.js 讓它改用自己的資料庫。
- LINE／Email 實際發送通知尚未實作。
