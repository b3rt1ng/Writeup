🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# DNA Extraction

## Context
We are given a network capture `challenge.pcap`. The goal is to find a flag inside it.

## Analysis
Opening the capture, we observe a large number of **DNS requests** to the same domain,
where the **first subdomain (label)** is each time a random 20-character string of
lowercase letters/digits (e.g. `kjeumrrwaeaaav2fijif`, `mubyjquqcaaaf4vucdaa`, ...).

This pattern is characteristic of **data exfiltration via DNS tunneling**: the attacker
splits a file into chunks, encodes each chunk (in base32, an alphabet compatible with DNS
naming constraints, i.e. lowercase letters + digits), and sends each chunk as a subdomain of a
DNS request to a server they control.

## Exploitation
1. **Extraction**: with Scapy, we go through the pcap and collect, in order of appearance, the first label of each DNS request (`qname.split('.')[1]`), deduplicating along the way.
2. **Reconstruction**: we concatenate all these labels end to end, in order.
3. **Decoding**: the resulting string is uppercased, padded to a multiple of 8 characters, then decoded as **Base32** (`base64.b32decode`).
4. The resulting binary data starts with the `RIFF...WEBP` signature, so it's a **WebP** image, which we save directly (`flag.webp`).

```python
from scapy.all import rdpcap, DNS, DNSQR
import base64

subs = []
for pkt in rdpcap("challenge.pcap"):
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        name = pkt[DNSQR].qname.decode().rstrip('.')
        sub = name.split('.')[1]
        if sub not in subs:
            subs.append(sub)

concat = ''.join(subs).upper()
concat += '=' * ((8 - len(concat) % 8) % 8)
open("flag.webp", "wb").write(base64.b32decode(concat))
```

## Result
The image `flag.webp` (300×50 px, so remember to zoom in a bit) directly displays the flag in clear text.
```
404CTF{CL4UD3_B3RN4RD_G0T_PWNED}!
```
