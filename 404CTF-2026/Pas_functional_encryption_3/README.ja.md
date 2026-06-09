🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# Writeup: Pas Functional Encryption（パート3）

## コンテキスト

スキームは前のパートと同一（NIST P-256上のIPFE）だが、2つの変更がパート2の攻撃を破る。復元すべき秘密ベクトルは$\text{rv} \in \{0,1\}^{255} \times \{1\}$：最後のビットは**1に固定**。鍵クエリのベクトルは最後の座標に**ノイズ**を加えて生成される：

$$y = (y_0, \ldots, y_{254}, a) \quad \text{ここで } a \xleftarrow{\$} \mathbb{F}_n$$

暗号化はパート2と同じ（$E_i = (\alpha \cdot y_i) \cdot g + r \cdot h_i$）なので、鍵クエリの復号は依然として$T = d \cdot G'$（$G' = \alpha \cdot g$）を与えるが、今度は：

$$T = \bigl(\underbrace{y[:255] \cdot \text{rv}[:255]}_{d_{\text{bin}} \in \{0..255\}} + \underbrace{a}_{\text{既知、巨大}}\bigr) \cdot G'$$

項$a$は既知（サーバーが返す）だが$\mathbb{F}_n$でランダムなので、$T$はランダムなEC点のように見える。もはや有界な表を構築して直接検索することはできない。

## サーバー

`TRIES = 5`、`INSTANCE_TRIES = 64` → 320クエリ、64回ごとにリキー。暗号文はパート2と同様にキャッシュされる：$\alpha$と$G'$はサイクル内で定数。

## 脆弱性

脆弱性はパート2と同じ：$G' = \alpha \cdot g$は**サイクル内で定数**。すべての$T_i = (d_i + a_i) \cdot G'$が同じ未知の基底を共有する。しかし$a_i$が大きいため、直接正規化することはできない。

アイデアは同じサイクルの2つのクエリに対してmeet-in-the-middleを使い、**$G'$を明示的に回復する**こと。

## 攻略

### ステップ1：meet-in-the-middleによる$G'$の回復

同じサイクルの2つのクエリ$i$と$j$に対して：

$$T_i = (d_i + a_i) \cdot G', \qquad T_j = (d_j + a_j) \cdot G'$$

ここで$a_i, a_j$は既知、$d_i, d_j \in \{0..255\}$は未知。$G'$を消去すると：

$$d_j \cdot T_i - d_i \cdot T_j = a_i \cdot T_j - a_j \cdot T_i =: R$$

$R$は完全に計算可能なEC点。方程式は次のように書き換えられる：

$$d_j \cdot T_i = R + d_i \cdot T_j$$

meet-in-the-middleを設定：
- **Baby steps**：$\mathcal{L} = \{k \cdot T_j \mapsto k : k = 0..255\}$を事前計算
- **Giant steps**：$d_j = 0..255$に対して$R + d_j \cdot T_i \in \mathcal{L}$かテスト

衝突から直接$(d_i, d_j)$が得られ、したがって：

$$G' = (d_i + a_i)^{-1} \cdot T_i$$

512回のEC演算で十分で、圧倒的な確率で衝突は一意。

### ステップ2：他のすべてのクエリの$d_k$を回復

$G'$が既知になれば、サイクルの各クエリ$k$に対して：

$$P_k = T_k - a_k \cdot G' = d_k \cdot G'$$

$d_k \in \{0..255\}$：$\{k \cdot G' : k = 0..255\}$を事前計算して$d_k$を直読みする。

### ステップ3：線形システムを解く

5サイクルにわたってペア$(y_i[:255] \in \{0,1\}^{255},\ d_i)$を蓄積する（rvは定数、$\alpha/g/s/t$は変わる）。$\text{rv}[255] = 1$は既知なので、解くべきシステムは$255 \times 255$サイズ：

$$A \cdot \text{rv}[:255] = b$$

$\mathbb{Q}$上で解き、$\{0,1\}$に丸めて最後のビットを付加：$\text{rv} = \text{rv}[:255] + [1]$。

$5 \times 63 = 315$サンプルで必要な255方程式を大きく超える。

## 結論

ノイズ保護（$a \in \mathbb{F}_n$）は$T_i$をランダム点と区別できなくしようとする。しかし$a_i$は**既知**であり、サイクル内のすべての$T_i$が同じ$G'$を共有するため、関係式$d_j \cdot T_i - d_i \cdot T_j = R$（右辺は計算可能）により問題は$\{0..255\}^2$上のmeet-in-the-middleに帰着する。$G'$を明示的に回復すれば、残りの攻撃は前のパートと同一。

---

#NOTE:

まずローカルでソルバーを作成した。[こちら](solver.py)で読むことができる。リモートソルバーはここには含めないが、チャレンジ2と同じ考え方。
