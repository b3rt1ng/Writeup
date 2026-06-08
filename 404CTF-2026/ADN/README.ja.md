🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# DNA抽出

## コンテキスト
ネットワークキャプチャファイル `challenge.pcap` が与えられる。目的はその中からフラグを見つけ出すこと。

## 解析
キャプチャを開くと、同じドメインに対する大量の **DNSリクエスト** が観察される。
それぞれの **最初のサブドメイン(ラベル)** は、毎回ランダムな20文字の小文字/数字の文字列
(例: `kjeumrrwaeaaav2fijif`、`mubyjquqcaaaf4vucdaa` など)になっている。

このパターンは **DNSトンネリングによるデータ流出** の特徴である。攻撃者はファイルを
チャンクに分割し、各チャンクをエンコードして(base32 — DNSの命名制約に適合するアルファベット、
すなわち小文字+数字)、各チャンクを自分が管理するサーバーへのDNSリクエストの
サブドメインとして送信する。

## 攻略
1. **抽出**: Scapyを使ってpcapを走査し、出現順に各DNSリクエストの最初のラベル(`qname.split('.')[1]`)を重複排除しながら収集する。
2. **再構築**: これらのラベルを順番通りに連結する。
3. **デコード**: 得られた文字列を大文字に変換し、8文字の倍数になるようパディングしてから **Base32** でデコードする(`base64.b32decode`)。
4. 得られたバイナリデータは `RIFF...WEBP` というシグネチャで始まっているので、これは **WebP** 画像であり、そのまま保存する(`flag.webp`)。

```python
from scapy.all import rdpcap, DNS, DNSQR
import base64

subs = []
for pkt in rdpcap("challenge.pcap"):
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        name = pkt[DNSQR].qname.decode().rstrip('.')
        sub = name.split('.')[1]
        if sub not in subs:
            subs.append(sub)

concat = ''.join(subs).upper()
concat += '=' * ((8 - len(concat) % 8) % 8)
open("flag.webp", "wb").write(base64.b32decode(concat))
```

## 結果
画像 `flag.webp`(300×50ピクセル、少しズームすることを忘れずに)に、フラグがそのまま表示される。
```
404CTF{CL4UD3_B3RN4RD_G0T_PWNED}!
```
