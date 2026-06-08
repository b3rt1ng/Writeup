🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# Extraction D'ADNs

## Contexte
On nous fournit une capture réseau `challenge.pcap`. L'objectif est d'y retrouver un flag.

## Analyse
En ouvrant la capture, on observe un grand nombre de **requêtes DNS** vers un même domaine,
dont le **premier sous-domaine (label)** est à chaque fois une chaîne aléatoire de 20
caractères en minuscules/chiffres (ex: `kjeumrrwaeaaav2fijif`, `mubyjquqcaaaf4vucdaa`, ...).

Ce pattern est caractéristique d'une **exfiltration de données via tunneling DNS** :
l'attaquant découpe un fichier en morceaux, encode chaque morceau (en base32, l'alphabet
étant compatible avec les contraintes de nommage DNS — minuscules + chiffres), et envoie
chaque morceau comme sous-domaine d'une requête DNS vers un serveur qu'il contrôle.

## Exploitation
1. **Extraction** : avec Scapy, on parcourt le pcap et on récupère, dans l'ordre d'apparition, le premier label de chaque requête DNS (`qname.split('.')[1]`), en dédupliquant.
2. **Reconstruction** : on concatène tous ces labels bout à bout, dans l'ordre.
3. **Décodage** : la chaîne obtenue est mise en majuscules, paddée à un multiple de 8 caractères, puis décodée en **Base32** (`base64.b32decode`).
4. Le résultat binaire commence par la signature `RIFF...WEBP`, c'est donc une image **WebP** on l'enregistre directement (`flag.webp`).

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

## Résultat
L'image `flag.webp` (300×50 px, donc pensez à zoomer un peu) affiche directement le flag en clair.
```
404CTF{CL4UD3_B3RN4RD_G0T_PWNED}!
```