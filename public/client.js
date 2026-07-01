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
  var sanitizationFired = false
  comments.forEach(function (c) {
    const div = document.createElement('div')
    div.className = 'comment-item'
    if (xssProtection) {
      const sanitized = DOMPurify.sanitize(c)
      if (sanitized !== c) sanitizationFired = true
      div.innerHTML = sanitized
    } else {
      div.innerHTML = c
    }
    area.appendChild(div)
  })

  if (sanitizationFired && window.highlightDefense) {
    window.highlightDefense('xss_dompur')
  }
})()
