# Writeups

Personal collection of CTF writeups, available in English, French, and Japanese.

## <img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcS6PwGYawa5tdEF66L7-UEpgTkcdZ4F3D1YnA&s" style>

| Machine | Difficulty | OS | Type | EN | FR | JA |
|---------|------------|-----|------|:--:|:--:|:--:|
| Garfield | Hard | Windows | Active Directory | [EN](HackTheBox/Garfield/README.md) | [FR](HackTheBox/Garfield/README.fr.md) | [JA](HackTheBox/Garfield/README.ja.md) |
| DevArea | Medium | Linux | Web / Middleware | [EN](HackTheBox/DevArea/README.md) | [FR](HackTheBox/DevArea/README.fr.md) | [JA](HackTheBox/DevArea/README.jp.md) |
| Kobold | Easy | Linux | Web / Docker | [EN](HackTheBox/Kobold/README.md) | [FR](HackTheBox/Kobold/README.fr.md) | [JA](HackTheBox/Kobold/README.ja.md) |
| Silentium | Easy | Linux | Web / CVE Chain | [EN](HackTheBox/Silentium/README.md) | [FR](HackTheBox/Silentium/README.fr.md) | [JA](HackTheBox/Silentium/README.ja.md) |
| MonitorsThree | Medium | Linux | Web / SQLi / CVE | [EN](HackTheBox/MonitorsThree/README.md) | [FR](HackTheBox/MonitorsThree/README.fr.md) | [JA](HackTheBox/MonitorsThree/README.ja.md) |
| Logging | Medium | Windows | Active Directory / WSUS / ADCS | [EN](HackTheBox/Logging/README.md) | [FR](HackTheBox/Logging/README.fr.md) | [JA](HackTheBox/Logging/README.ja.md) |
| PingPong | Insane | Windows | Active Directory / Cross-Forest Trust / ADCS | [EN](HackTheBox/PingPong/README.md) | [FR](HackTheBox/PingPong/README.fr.md) | [JA](HackTheBox/PingPong/README.ja.md) |
| Reactor | Easy | Linux | Web / Node.js Inspector / Privilege Escalation | [EN](HackTheBox/Reactor/README.md) | [FR](HackTheBox/Reactor/README.fr.md) | [JA](HackTheBox/Reactor/README.ja.md) |
| DevHub | Medium | Linux | Web / API | [EN](HackTheBox/DevHub/README.md) | [FR](HackTheBox/DevHub/README.fr.md) | [JA](HackTheBox/DevHub/README.ja.md) |


---

## <img src="https://dojo-yeswehack.com/YWH_DOJO_2023-Black.svg" height="60">

| Challenge | Type | Language |
|-----------|------|:--:|
| Dojo #46 | Command Injection / Unicode NFKC Normalization Bypass (RCE) | [EN](YesWeHackDojo/46/README.en.md) |
| Dojo #48 | Unsafe Object Deserialization via `Oj.load` (RCE) | [EN](YesWeHackDojo/48/README.en.md) |
| Dojo #49 | Linux Wildcard Injection in `cp *` (File Disclosure) | [EN](YesWeHackDojo/49/README.en.md) |
| Dojo #50 | Path Traversal / HMAC Signature Bypass (CRLF Injection) | [EN](YesWeHackDojo/50/README.en.md) |
| Dojo #51 | ZIP Path Traversal / `eval()` (RCE) | [EN](YesWeHackDojo/51/README.en.md) |


---

## <img src="https://www.404ctf.fr/assets/2026/logos/logo_404_2026.svg" height="120" style="vertical-align: middle;"> 404 CTF

| Challenge | Type | GOTO |
|-----------|------|:--:|
| Extraction d'ADNs | Forensics | [EN](404CTF-2026/ADN/README.md) - [FR](404CTF-2026/ADN/README.fr.md) - [JA](404CTF-2026/ADN/README.ja.md) |
| Wall Of Patents | Web | [EN](404CTF-2026/Wall_Of_Patents/README.md) - [FR](404CTF-2026/Wall_Of_Patents/README.fr.md) - [JA](404CTF-2026/Wall_Of_Patents/README.ja.md) |
| Web-Scientos | Web | [EN](404CTF-2026/Web-Scientos/README.md) - [FR](404CTF-2026/Web-Scientos/README.fr.md) - [JA](404CTF-2026/Web-Scientos/README.ja.md) |



---
## Why is there some missing writeup ?
The ones that are missing are ongoing challenges and writeups (for those), are not allowed to be posted publicly. Patience !

I still add the name of the challenges I did as a POC (Proof Of Competence).

## How I make my writeups

When doing my challenges, I have a little python note CLI where I put my findings, comments, notes, as well as the history of my commands. This way when I get the flags, I can easily realy on my paths registration. It then generates me a Markdown resume of my notes that i just need to correct and further explain. It then translate the whole file in French then Japanese (my targets audience / recrutors) and puts it here.

Note that for my DOJOs, the reports are made entirely by hand so as of now there's only the english version.