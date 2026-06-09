🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# Writeup : Pas Functional Encryption

## Contexte

Le challenge implémente un schéma de chiffrement fonctionnel à produit scalaire (IPFE), tel que décrit dans [eprint 2015/608](https://eprint.iacr.org/2015/608.pdf), sur la courbe NIST P-256.

Paramètres :

- deux générateurs aléatoires $g, h$ sur la courbe $E$
- une clé maîtresse composée de deux vecteurs secrets $s, t \in \mathbb{F}_q^{256}$
- des paramètres publics $h_i = s_i \cdot g + t_i \cdot h$

Chiffrement d'un vecteur binaire $y$ (avec $r$ aléatoire) :

$$C = r \cdot g, \quad D = r \cdot h, \quad E_i = y_i \cdot g + r \cdot h_i$$

Génération d'une clé fonctionnelle pour un vecteur $x$ :

$$sk_x = (s \cdot x,\ t \cdot x)$$

Déchiffrement avec $sk_x = (sx, tx)$ :

$$\sum_i x_i E_i - sx \cdot C - tx \cdot D = (x \cdot y) \cdot g$$

Il ne reste plus qu'à résoudre un logarithme discret pour retrouver $x \cdot y$, ce qui n'est faisable que si cette valeur reste petite.

## Le serveur

Le menu propose trois actions :

1. **Get a key for a vector** : le serveur tire lui-même un vecteur binaire aléatoire $x$ et renvoie $\{g, sx, tx, x\}$, c'est-à-dire la clé fonctionnelle **et** le vecteur en clair
2. **Get an encrypted vector** : chiffre une seule fois un vecteur secret binaire aléatoire (la cible à retrouver) et renvoie $(C, D, E_i)$
3. **Check** : il faut deviner exactement ce vecteur secret pour obtenir le flag

## La faille

Dans un IPFE correctement utilisé, l'oracle de génération de clé ne devrait répondre qu'à des requêtes sur des fonctions choisies par l'attaquant, et encore avec des restrictions fortes pour ne pas fuiter d'information sur le vecteur chiffré.

Ici, le serveur génère lui-même le vecteur $x$ utilisé pour la clé... et le donne directement en clair en même temps que $sk_x$. Chaque appel à l'option 1 fournit donc gratuitement un couple $(x_i, sk_{x_i})$ permettant de calculer :

$$T = \sum_k x_i[k]\, E_k - sx_i \cdot C - tx_i \cdot D = (x_i \cdot \text{secret}) \cdot g$$

Comme `secret` et chaque $x_i$ sont des vecteurs binaires de longueur 256, le produit scalaire $d_i = x_i \cdot \text{secret}$ est un entier compris entre 0 et 256. Le logarithme discret devient trivial : il suffit de précalculer $0 \cdot g, 1 \cdot g, \dots, 256 \cdot g$ et de comparer.

## Exploitation

En répétant l'opération 1 environ 298 fois, on obtient un système linéaire $A v = b$ où :

- chaque ligne de $A$ est un vecteur binaire connu $x_i$
- $b_i = d_i = x_i \cdot \text{secret}$
- $v = \text{secret}$ est l'inconnue à retrouver

La matrice $A$ (256 colonnes, suffisamment de lignes) est inversible avec une forte probabilité. On résout le système sur $\mathbb{Q}$, on arrondit chaque coordonnée à 0 ou 1, et on obtient le vecteur secret complet. Il ne reste plus qu'à l'envoyer via l'option 3 pour récupérer le flag.

## Conclusion

La vulnérabilité tient en une ligne : l'oracle de génération de clé fuit le vecteur aléatoire utilisé en plus de la clé fonctionnelle elle-même. Un schéma censé ne révéler que des produits scalaires *choisis* devient ainsi un oracle de mesures linéaires *connues* sur le secret, ce qui permet de le reconstruire entièrement par simple algèbre linéaire.
