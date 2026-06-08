🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# Web - Scientos

## TL;DR

`ScientosNet` est un faux réseau social de scientifiques. Le flag est affiché sur la page
d'accueil uniquement pour les comptes dont l'email se termine par `@scientos-admin.net` et
qui sont **vérifiés**. La vérification de compte repose sur un jeton (UUID) envoyé par mail,
mais la requête SQL qui va chercher ce jeton concatène l'email **sans échappement**.

En contournant la liste noire anti-injection avec un payload `CASE WHEN ... THEN PG_SLEEP(1)
ELSE PG_SLEEP(0) END`, on exfiltre le jeton d'activation caractère par caractère via une
**injection SQL aveugle basée sur le temps (stacked queries)**, on active n'importe quel
compte `@scientos-admin.net`, puis on se connecte pour récupérer le flag.

## Architecture

Le challenge est composé de 4 services (`docker-compose.yml`) :

- **web** (Express / EJS, port 3002) : le site principal, inscription / connexion / page d'accueil avec le flag
- **mailer** (port 3001) : simule une boîte mail interne consultable depuis `/mailer`
- **proxy** (nginx) : reverse-proxy exposant `web` et `mailer`
- **db** : PostgreSQL 16

Le code source de `web` est le seul pertinent pour cette vulnérabilité.

## 1. Comment obtenir le flag

`server.js` :

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

`utils.js` :

```js
export function isAdministrator(user) {
    const email = extractEmail(user?.email || "");
    return email?.endsWith("@scientos-admin.net");
}
```

`req.user` est peuplé depuis le cookie JWT `auth_token` posé au login (`router.js`). Donc pour
voir le flag il faut :

1. un compte dont l'email finit par `@scientos-admin.net` ;
2. ce compte doit être **`verified = true`** (sinon `/api/auth/login` refuse la connexion) ;
3. connaître le mot de passe de ce compte pour récupérer le cookie de session.

Rien n'empêche de **créer soi-même** un tel compte via `/api/auth/register`, le seul obstacle
est l'étape de vérification par email, qui nécessite un jeton secret stocké côté serveur.

## 2. La faille : injection SQL dans `getToken`

`db.js` :

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

`email` est injecté **brut** dans la requête (concaténation de chaînes), sans paramètre lié.
`getToken` est appelée depuis `GET /api/auth/validate` :

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

Injection SQL classique via le paramètre `email` de `/api/auth/validate`.

### Détail technique : pourquoi les requêtes empilées (`; ... --`) fonctionnent

`pool.query("SELECT ... '${email}'")` est appelé **sans tableau de paramètres**. Le driver
`pg` utilise alors le *simple query protocol* de PostgreSQL, qui autorise plusieurs
instructions séparées par `;` dans une seule requête. On peut donc « fermer » la requête
d'origine et empiler une requête arbitraire :

```sql
SELECT id FROM users WHERE email = 'inexistant'; <NOTRE REQUÊTE> --'
```

## 3. Contourner le filtre `isClearString`

`utils.js` :

```js
const blocklistRegex = /\b(?:union|and|or)\b|\||&|\/|#/;

export function isClearString(input) {
    if (typeof input === "string") {
        return !blocklistRegex.test(input.toLowerCase());
    }
    return false;
}
```

La liste noire bloque les mots `union`, `and`, `or` (en tant que mots entiers) ainsi que
`|`, `&`, `/`, `#`. C'est suffisant pour bloquer toutes les injections « classiques »
(`' OR 1=1 --`, `UNION SELECT ...`, commentaires `#` ou `/* */`, etc.).

**Mais** il est possible d'écrire une condition booléenne sans jamais utiliser `AND`/`OR`/
`UNION`, en utilisant un `CASE WHEN ... THEN ... ELSE ... END`, aucun de ces mots-clés
n'est filtré :

```sql
SELECT CASE WHEN (<condition>) THEN PG_SLEEP(1) ELSE PG_SLEEP(0) END
```

Le commentaire de fin de requête utilise `--` (tiret double), absent de la liste noire,
plutôt que `#` ou `/* */`.

## 4. Exfiltration aveugle du jeton (time-based blind SQLi)

Le jeton d'activation est un UUID v4 (36 caractères : `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`,
alphabet `0-9a-f-`). On le récupère caractère par caractère en mesurant le temps de réponse :

```sql
inexistant';
SELECT CASE WHEN
    (SUBSTRING(
        (SELECT value FROM tokens WHERE userId = (SELECT id FROM users WHERE email='<EMAIL_CIBLE>') LIMIT 1),
        <position>, 1
    ) = '<caractère_testé>')
    THEN PG_SLEEP(1)
    ELSE PG_SLEEP(0)
END --
```

Pour chaque position (1 à 36) et chaque caractère candidat de `0123456789abcdef-`, on envoie
ce payload via `GET /api/auth/validate?email=<payload>&token=test` et on mesure la durée de
la réponse :

- si elle dépasse ~0,8 s, la condition est vraie, c'est le bon caractère ;
- sinon on passe au caractère suivant.

Au bout de 36 × 17 requêtes au pire, on obtient le jeton d'activation complet de n'importe
quel compte (par email), **sans connaître le mot de passe ni avoir accès à la boîte mail**.

## 5. Activer le compte et se connecter

Une fois le jeton récupéré :

1. **Inscription** d'un compte avec un email `xxxx@scientos-admin.net` (`POST /api/auth/register`).
2. **Exfiltration** du jeton d'activation de ce compte via l'injection ci-dessus.
3. **Validation** du compte : `GET /api/auth/validate?email=<email>&token=<jeton_extrait>`,
   ce qui passe `verified = true` en base.
4. **Connexion** : `POST /api/auth/login` avec `email` + `password`.

### Piège sur le mot de passe

`auth-router.js` (login) :

```js
const passwordBuffer = Buffer.from(password, "hex");
const realPasswordBuffer = Buffer.from(userData.password, "hex");
if (passwordBuffer.length === realPasswordBuffer.length && timingSafeEqual(passwordBuffer, realPasswordBuffer)) {
```

On pourrait croire (comme l'indiquait un commentaire dans une première version du script)
que le mot de passe est haché côté serveur et qu'il faut envoyer un SHA-256. **C'est faux** :
`createUser` (`db.js`) stocke le mot de passe **tel quel**, sans aucun hachage :

```js
async function createUser(email, username, password) {
    await createUserWithId(availableUserId++, email, username, password);
}
```

Le `Buffer.from(x, "hex")` des deux côtés ne sert qu'à comparer en temps constant
(`timingSafeEqual`) deux chaînes hexadécimales, **pas** à vérifier un hash. Il suffit donc
de choisir un mot de passe à l'inscription qui soit lui-même de l'hexadécimal valide
(par ex. `aabbccdd`) et de renvoyer **exactement la même chaîne** au login. Envoyer un
SHA-256 (64 caractères hex = 32 octets) échoue car sa longueur décodée (32) ne correspond
pas à celle du mot de passe stocké (4 octets pour `aabbccdd`), et la comparaison
`passwordBuffer.length === realPasswordBuffer.length` échoue avant même `timingSafeEqual`.

5. Le serveur pose alors un cookie `auth_token` (JWT signé HS256), `req.user` est rempli,
   `isAdministrator` renvoie `true`, et `GET /` affiche le flag.