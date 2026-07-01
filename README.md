# xss-csrf-demo

XSS・CSRF をインタラクティブに体験できるデモ環境。

## 必要なもの

- Node.js（v18 以上）
- `/etc/hosts` に以下の2行を追加（要 sudo）

```
127.0.0.1  bank.local
127.0.0.1  attacker.local
```

```sh
sudo sh -c 'echo "127.0.0.1  bank.local" >> /etc/hosts'
sudo sh -c 'echo "127.0.0.1  attacker.local" >> /etc/hosts'
```

## セットアップ

```sh
git clone https://github.com/okawara0618info-coder/xss-csrf-demo.git
cd xss-csrf-demo
npm install
```

## 起動

ターミナルを2つ開いて、それぞれで実行する。

```sh
# ターミナル1 — 銀行サイト（被害者）
node victim.js
```

```sh
# ターミナル2 — 攻撃者サイト
node attacker.js
```

## アクセス

| サイト | URL | 説明 |
|---|---|---|
| bank.local | http://bank.local:3000 | 被害者サイト（銀行）。ログイン: ユーザー名は何でもOK、パスワードは `pass` |
| attacker.local | http://attacker.local:3001 | 攻撃者サイト |
