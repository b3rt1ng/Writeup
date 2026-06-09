🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# Writeup: Pas Functional Encryption（パート2）

## コンテキスト

このチャレンジはパート1と同じNIST P-256上のIPFEスキームを使用しているが、暗号化に重要な変更が加えられている。秘密ベクトル$\text{rv} \in \{0,1\}^{256}$は次のように暗号化される（$r, \alpha$はランダム）：

$$C = r \cdot g, \quad D = r \cdot h, \quad E_i = y_i \cdot (\alpha \cdot g) + r \cdot h_i$$

ベクトル$x$に対する関数鍵は同じ：

$$sk_x = (s \cdot x,\ t \cdot x)$$

復号結果は：

$$\sum_i x_i E_i - sx \cdot C - tx \cdot D = (x \cdot y) \cdot \alpha g = d \cdot G'$$

ここで$G' = \alpha \cdot g$は**未知のランダム点**。パート1と異なり、結果は$g$の既知の倍数ではなく、$d$に関する情報は$\alpha$でマスクされている。

## サーバー

メニューはパート1と同じ3つのアクションを提供するが、予算制限がある：`TRIES = 7`サイクル × `INSTANCE_TRIES = 64`クエリ、計448クエリ。新しいサイクルごとにパラメータ$g, h, s, t$が再生成（リキー）されるが、秘密ベクトル$\text{rv}$は同じままである。

## 脆弱性

サーバーは同じサイクル内でのアクション2呼び出し間で暗号文をキャッシュする：

```python
if ciphertext is None:
    ciphertext = encrypt(g, h, hi, random_vector)
```

結果：あるサイクル内では$\alpha$は**固定**であり、したがって$G' = \alpha \cdot g$は定数。すべての復号結果$T_i = d_i \cdot G'$は同じ未知点の倍数。その比率は保存される：

$$d_{\text{ref}} \cdot T_j = d_j \cdot T_{\text{ref}}$$

よって$\alpha$を知らなくても$d_i = x_i \cdot \text{rv}$の値を回復できる。

## 攻略

各サイクルで、まずアクション2を呼び出して暗号文（したがって$\alpha$）を固定し、次に残り63回アクション1を呼び出す。受け取った各ペア$(x_i, sk_{x_i})$に対して、復号により$T_i = d_i \cdot G'$を計算する。

サイクルの結果から非ゼロの$T_{\text{ref}}$を任意に選ぶ。集合$\{k \cdot T_{\text{ref}} : k = 0..256\}$を事前計算し、いくつかの非ゼロ$T_j$に対して$c \cdot T_j$がこの集合に属するような候補$c \in \{1..256\}$を探すことで$d_{\text{ref}}$を回復する。その後$d_i = S[d_{\text{ref}} \cdot T_i]$を通じてすべての$d_i$を導出する。

7サイクル後、$7 \times 63 = 441$個のペア$(x_i, d_i)$が得られる。256個の線形独立なベクトル$x_i$を選んでシステムを構成：

$$A \cdot \text{rv} = b$$

$\mathbb{Q}$上で解き、$\{0, 1\}$に丸めて、アクション3から結果を送信してフラグを取得。

## 結論

脆弱性は暗号文キャッシュに起因する：$\alpha$をサイクル全体で固定することで、サーバーは復号結果を共線にしてしまう。この一貫性により$G'$を知らなくても$d_i$を正規化でき、保護に見えたもの（マスク$\alpha$）が無声の定数になる。その後の攻略はパート1と同じ：蓄積された測定値への線形代数。

#NOTE:

まずローカルでソルバーを作成した。[こちら](solver.py)で読むことができる。フラグを取得するにはnetcatサーバーと対話する必要があり、[pwntools](https://docs.pwntools.com/en/stable/)を使ってCLIとの対話を自動化する。そのソルバーは[こちら](solve_remote.py)で確認できる。
