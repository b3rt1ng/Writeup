🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# Writeup : Pas Functional Encryption (partie 3)

## Contexte

Le schéma reste identique aux parties précédentes (IPFE sur NIST P-256), mais deux changements cassent l'attaque de la partie 2. Le vecteur secret à retrouver est maintenant $\text{rv} \in \{0,1\}^{255} \times \{1\}$ : le dernier bit est **fixé à 1**. Les vecteurs des requêtes de clé sont générés avec un **bruit** sur la dernière coordonnée :

$$y = (y_0, \ldots, y_{254}, a) \quad \text{où } a \xleftarrow{\$} \mathbb{F}_n$$

Le chiffrement reste le même qu'en partie 2 ($E_i = (\alpha \cdot y_i) \cdot g + r \cdot h_i$), donc le déchiffrement d'une requête de clé donne toujours $T = d \cdot G'$ avec $G' = \alpha \cdot g$, mais maintenant :

$$T = \bigl(\underbrace{y[:255] \cdot \text{rv}[:255]}_{d_{\text{bin}} \in \{0..255\}} + \underbrace{a}_{\text{connu, énorme}}\bigr) \cdot G'$$

Le terme $a$ est connu (retourné par le serveur), mais il est aléatoire dans $\mathbb{F}_n$, donc $T$ ressemble à un point EC aléatoire. On ne peut plus construire une table bornée et faire une recherche directe.

## Le serveur

`TRIES = 5`, `INSTANCE_TRIES = 64` → 320 requêtes, re-keying toutes les 64. Le chiffré est mis en cache exactement comme en partie 2 : $\alpha$ et $G'$ sont constants dans un cycle.

## La faille

La faille est la même qu'en partie 2 : $G' = \alpha \cdot g$ est **constant dans un cycle**. Tous les $T_i = (d_i + a_i) \cdot G'$ partagent la même base inconnue. Mais comme $a_i$ est grand, on ne peut plus normaliser directement.

L'idée est de **retrouver $G'$ explicitement** grâce à un meet-in-the-middle sur deux requêtes du même cycle.

## Exploitation

### Étape 1: Retrouver $G'$ par meet-in-the-middle

Pour deux requêtes $i$ et $j$ d'un même cycle :

$$T_i = (d_i + a_i) \cdot G', \qquad T_j = (d_j + a_j) \cdot G'$$

où $a_i, a_j$ sont connus et $d_i, d_j \in \{0..255\}$ sont inconnus. En éliminant $G'$, on obtient :

$$d_j \cdot T_i - d_i \cdot T_j = a_i \cdot T_j - a_j \cdot T_i =: R$$

$R$ est un point EC entièrement calculable. L'équation se réécrit :

$$d_j \cdot T_i = R + d_i \cdot T_j$$

On pose alors le meet-in-the-middle :
- **Baby steps** : précalculer $\mathcal{L} = \{k \cdot T_j \mapsto k : k = 0..255\}$
- **Giant steps** : pour $d_j = 0..255$, tester si $R + d_j \cdot T_i \in \mathcal{L}$

Une collision donne directement $(d_i, d_j)$, et donc :

$$G' = (d_i + a_i)^{-1} \cdot T_i$$

512 opérations EC suffisent, et la collision est unique avec une probabilité écrasante.

### Étape 2: Récupérer les $d_k$ pour toutes les autres requêtes

Une fois $G'$ connu, pour chaque requête $k$ du cycle :

$$P_k = T_k - a_k \cdot G' = d_k \cdot G'$$

$d_k \in \{0..255\}$ : on précompute $\{k \cdot G' : k = 0..255\}$ et on lit $d_k$ directement.

### Étape 3: Résoudre le système linéaire

On accumule des paires $(y_i[:255] \in \{0,1\}^{255},\ d_i)$ sur les 5 cycles (rv constant, $\alpha/g/s/t$ changent). On connaît déjà $\text{rv}[255] = 1$, donc le système à résoudre est de taille $255 \times 255$ :

$$A \cdot \text{rv}[:255] = b$$

On résout sur $\mathbb{Q}$, on arrondit à $\{0,1\}$, et on recolle le dernier bit : $\text{rv} = \text{rv}[:255] + [1]$.

Avec $5 \times 63 = 315$ samples disponibles, on dépasse largement les 255 équations nécessaires.

## Conclusion

La protection par bruit ($a \in \mathbb{F}_n$) cherche à rendre les $T_i$ indiscernables de points aléatoires. Mais puisque $a_i$ est **connu** et que tous les $T_i$ du cycle partagent le même $G'$, la relation $d_j \cdot T_i - d_i \cdot T_j = R$ (dont le membre droit est calculable) ramène le problème à un meet-in-the-middle sur $\{0..255\}^2$. Une fois $G'$ explicitement retrouvé, le reste de l'attaque est identique aux parties précédentes.

---

#NOTE:

J'ai commencé par me faire mon petit solver en local, vous pouvez le lire [ici](solver.py). Pour je ne vais pas remettre le solver remote ici mais l'idée reste la même que pour le challenge 2
