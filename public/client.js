(function () {
  const data = window.__DEMO_DATA__
  if (!data) return

  const area = document.getElementById('comments-area')
  if (!area) return

  const comments = data.comments
  const xssProtection = data.xssProtection

  if (!comments || comments.length === 0) {
    area.innerHTML = '<p style="color:#aaa;font-size:13px">まだコメントなし — <a href="/comments">コメントを投稿する</a></p>'
    return
  }

  area.innerHTML = ''
  comments.slice(-5).forEach(function (c) {
    const div = document.createElement('div')
    div.className = 'comment-item'
    if (xssProtection) {
      // DOMPurify: HTMLタグを残しつつ onerror / script などの危険な部分だけ除去
      div.innerHTML = DOMPurify.sanitize(c)
    } else {
      // 生の innerHTML（v-html 相当）— 危険
      div.innerHTML = c
    }
    area.appendChild(div)
  })
})()
