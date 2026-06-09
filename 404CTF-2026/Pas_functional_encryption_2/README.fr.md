🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# Writeup : Pas Functional Encryption (partie 2)

## Contexte

Le challenge reprend le même schéma IPFE sur NIST P-256 que la partie 1, avec un changement important dans le chiffrement. Le vecteur secret $\text{rv} \in \{0,1\}^{256}$ est chiffré ainsi (avec $r, \alpha$ aléatoires) :

$$C = r \cdot g, \quad D = r \cdot h, \quad E_i = y_i \cdot (\alpha \cdot g) + r \cdot h_i$$

La clé fonctionnelle pour un vecteur $x$ reste la même :

$$sk_x = (s \cdot x,\ t \cdot x)$$

Le déchiffrement donne maintenant :

$$\sum_i x_i E_i - sx \cdot C - tx \cdot D = (x \cdot y) \cdot \alpha g = d \cdot G'$$

où $G' = \alpha \cdot g$ est un point **inconnu et aléatoire**. Contrairement à la partie 1, le résultat n'est plus un multiple connu de $g$ : l'information sur $d$ est masquée par $\alpha$.

## Le serveur

Le menu expose les mêmes trois actions que dans la partie 1, avec une contrainte de budget : `TRIES = 7` cycles de `INSTANCE_TRIES = 64` requêtes chacun, soit 448 requêtes au total. À chaque nouveau cycle, les paramètres $g, h, s, t$ sont régénérés (re-keying), mais le vecteur secret $\text{rv}$ reste le même.

## La faille

Le serveur met en cache le chiffré entre les appels à l'action 2 au sein d'un même cycle :

```python
if ciphertext is None:
    ciphertext = encrypt(g, h, hi, random_vector)
```

Conséquence : dans un cycle donné, $\alpha$ est **fixe** et donc $G' = \alpha \cdot g$ est constant. Tous les résultats de déchiffrement $T_i = d_i \cdot G'$ sont des multiples d'un même point inconnu. Leurs rapports sont préservés :

$$d_{\text{ref}} \cdot T_j = d_j \cdot T_{\text{ref}}$$

Il est donc possible de récupérer les valeurs $d_i = x_i \cdot \text{rv}$ sans jamais connaître $\alpha$.

## Exploitation

Pour chaque cycle, on commence par appeler l'action 2 pour fixer le chiffré (et donc $\alpha$), puis on appelle l'action 1 les 63 fois restantes. Pour chaque paire $(x_i, sk_{x_i})$ reçue, on calcule $T_i = d_i \cdot G'$ par déchiffrement.

On choisit un $T_{\text{ref}} \neq 0$ quelconque parmi les résultats du cycle. On précalcule l'ensemble $\{k \cdot T_{\text{ref}} : k = 0..256\}$, puis on retrouve $d_{\text{ref}}$ (l'entier inconnu associé à $T_{\text{ref}}$) en cherchant le candidat $c \in \{1..256\}$ tel que $c \cdot T_j$ appartient à cet ensemble pour une poignée de $T_j \neq 0$. On en déduit ensuite tous les $d_i$ via $d_i = S[d_{\text{ref}} \cdot T_i]$.

Après 7 cycles, on dispose de $7 \times 63 = 441$ paires $(x_i, d_i)$. On sélectionne 256 vecteurs $x_i$ linéairement indépendants pour former le système :

$$A \cdot \text{rv} = b$$

On résout sur $\mathbb{Q}$, on arrondit à $\{0, 1\}$, et on soumet le résultat via l'action 3 pour obtenir le flag.

## Conclusion

La vulnérabilité découle du cache du chiffré : en fixant $\alpha$ pour tout un cycle, le serveur rend les résultats de déchiffrement colinéaires. Cette cohérence permet de normaliser les $d_i$ sans connaître $G'$, transformant ce qui semblait être une protection (le masque $\alpha$) en une simple constante muette. L'exploitation reste ensuite identique à la partie 1 : algèbre linéaire sur les mesures accumulées.

#NOTE:

J'ai commencé par me faire mon petit solver en local, vous pouvez le lire [ici](solver.py). Pour récupérer le flag, il faut interragir avec un serveur netcat, et là on va utiliser [pwntools](https://docs.pwntools.com/en/stable/) pour automatiser les interractions avec le CLI, vous pouvez voir ce joli solver [ici](solve_remote.py)
