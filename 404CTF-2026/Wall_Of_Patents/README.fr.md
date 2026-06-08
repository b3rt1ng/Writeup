🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# Wall Of Patents - 404CTF

## Présentation du challenge

**PatentVault** est un service Flask où un utilisateur (identifié juste par un nom en session, sans auth réelle) peut déposer des « brevets » sous forme d'archive via `POST /post_patent` (extraite côté serveur dans `app/uploads/`) et récupérer un commentaire aléatoire via `GET /comment`. Le **FLAG** est inséré en base au premier démarrage et n'est normalement accessible qu'indirectement via un mécanisme de bot qui pioche des commentaires (`bot_outputs`) selon une fenêtre `seed` à deviner, sauf si on arrive à contourner complètement ce circuit.

## La vulnérabilité

Le point d'entrée intéressant est l'extraction d'archive (`app/utils.py`) :

```python
allowed_extensions = {'zip', 'gz', 'xz'}

def sanitize_filename(filename):
     blacklist = ["../", "..\\",  ".\\", "//", "..", "\\\\"]
     for pattern in blacklist:
        filename = filename.replace(pattern, "")
     while filename.startswith("/") or filename.startswith("\\"):
        filename = filename[1:]
     return filename

def extract_tar_archive(file, path='app/uploads/'):
    tar = tarfile.open(fileobj=file)
    for member in tar.getmembers():
         clean_name = sanitize_filename(member.name)
         member.name = clean_name
         tar.extract(member, path=path, filter='fully_trusted')
```

Deux failles se combinent :

1. **`sanitize_filename` ne nettoie que `member.name`**, c'est-à-dire le chemin de l'entrée dans l'archive, jamais `member.linkname`, qui est la **cible d'un lien symbolique**. La blacklist anti path-traversal est donc totalement hors-jeu pour les liens symboliques : on peut créer une entrée de type *symlink* dont le nom est inoffensif mais dont la cible pointe n'importe où sur le système de fichiers.

2. L'extraction est faite avec **`filter='fully_trusted'`**, qui (contrairement aux filtres `data`/`tar` introduits par la PEP 706) ne bloque ni la création de symlinks arbitraires ni les écritures qui traversent un symlink. Une fois le lien créé, n'importe quel membre suivant de l'archive dont le chemin *passe par* ce lien sera extrait à l'endroit réellement visé par le lien (résolution classique du système de fichiers), et ce, sans repasser par `sanitize_filename` puisque c'est le système qui résout le chemin, pas le code Python.

**Résultat : une primitive d'écriture de fichier arbitraire**, limitée par les droits du process Flask (UID `65534`, propriétaire de `/app` d'après le `Dockerfile`, donc suffisant pour écrire dans son propre code source).

### La cible : `app/database.py`

Le fichier `app/database.py` est un module Python normal, importé par l'application (`from app.database import ...`). Si on parvient à l'écraser, et que le serveur **recharge** ce module, on exécute du code arbitraire dans le contexte de l'app.

Or `app.py` lance Flask avec `debug=True` :

```python
app.run(host="0.0.0.0", port=3000, debug=True)
```

Le **reloader Werkzeug** surveille les fichiers `.py` du projet et redémarre automatiquement le serveur dès qu'il détecte une modification : il suffit donc d'écraser `app/database.py` et d'attendre quelques secondes pour que le code malveillant soit chargé et exécuté.

### La chaîne d'exploitation

1. Construire une archive (`.tar.gz`) contenant :
   - une entrée de type **symlink** dont le nom (sanitizé, donc anodin) pointe, via `linkname` (jamais filtré), vers le répertoire `app/` de l'application (chemin relatif depuis `app/uploads/`, le dossier d'extraction) ;
   - une entrée fichier régulier dont le chemin **traverse ce symlink** et se termine par `database.py`, contenant un module de remplacement.
2. Uploader cette archive via `POST /post_patent` (authentifiée seulement par le nom de session, accessible à n'importe qui).
3. Au moment de l'extraction, `tarfile` crée le lien symbolique puis écrit le fichier malveillant *à travers* ce lien : `app/database.py` est écrasé sur le disque.
4. Le reloader Flask (`debug=True`) détecte le changement et relance le process avec le `database.py` malveillant chargé.
5. Le `database.py` malveillant redéfinit `search_comments()` pour renvoyer directement `os.environ["FLAG"]` au lieu d'aller chercher un commentaire aléatoire dans `bot_outputs`.
6. Un simple `GET /comment?name=...` (route `get_comment` → `search_comments()`) renvoie alors le flag tel quel, en JSON, sans avoir à attendre/manipuler le bot ni la table `seed`.

C'est une élégante manière de **contourner tout le mini-protocole bot/seed/`bot_outputs`** : au lieu de calculer la fenêtre exacte que le bot expose (`compute_range`) pour espérer tomber sur l'enregistrement contenant le FLAG, on remplace carrément la fonction qui lit en base par une fonction qui lit la variable d'environnement `FLAG`.

## Le payload (`evil_database.py`)

Module minimal injecté à la place de `app/database.py` :

```python
import os

def search_comments():
    flag = os.environ.get("FLAG", "404CTF{not_found}")
    return [{"id": 157, "comment": flag}]
```

> Note : l'app n'a besoin que de `search_comments` pour la route `/comment`, donc un stub minimal suffit (les autres fonctions du module réel, à savoir `init_db`, `search_patents`, `add_patent`, `add_comment`, `change_seed`, ne sont plus appelées une fois l'app déjà initialisée et la session déjà ouverte).

## Le script d'exploitation (`solver.py`)

`create_session()` ouvre une session avec un nom aléatoire, `generate_exploit_tar()` construit l'archive (symlink `link` → `app-flask/app` + `database.py` malveillant placé derrière ce lien), `upload_exploit()` l'envoie via `POST /post_patent`, et `get_flag()` attend le rechargement du serveur (`time.sleep(5)`, avec un retry si la requête tombe pendant le redémarrage) avant d'interroger `/comment` et de retourner directement le flag.

```
$ python3 solver.py
404CTF{...}
```

