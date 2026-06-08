🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# Wall Of Patents - 404CTF

## Challenge overview

**PatentVault** is a Flask service where a user (identified only by a name in the session, with no real authentication) can upload "patents" as an archive via `POST /post_patent` (extracted server-side into `app/uploads/`) and fetch a random comment via `GET /comment`. The **FLAG** is inserted into the database on first startup and is normally only accessible indirectly through a bot mechanism that picks comments (`bot_outputs`) according to a `seed` window that has to be guessed — unless one manages to fully bypass that whole circuit.

## The vulnerability

The interesting entry point is the archive extraction (`app/utils.py`):

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

Two flaws combine here:

1. **`sanitize_filename` only cleans `member.name`**, i.e. the path of the entry inside the archive, never `member.linkname`, which is the **target of a symbolic link**. The anti path-traversal blacklist is therefore completely useless against symlinks: one can create a *symlink* entry whose name is harmless but whose target points anywhere on the filesystem.

2. The extraction is performed with **`filter='fully_trusted'`**, which (unlike the `data`/`tar` filters introduced by PEP 706) blocks neither the creation of arbitrary symlinks nor writes that traverse a symlink. Once the link is created, any subsequent member of the archive whose path *goes through* that link will be extracted to the location actually pointed to by the link (standard filesystem path resolution), and this happens without ever going through `sanitize_filename` again, since it's the OS that resolves the path, not the Python code.

**Result: an arbitrary file write primitive**, limited only by the rights of the Flask process (UID `65534`, owner of `/app` according to the `Dockerfile`, hence sufficient to write into its own source code).

### The target: `app/database.py`

`app/database.py` is a regular Python module imported by the application (`from app.database import ...`). If we manage to overwrite it, and the server **reloads** that module, we execute arbitrary code in the app's context.

Now, `app.py` runs Flask with `debug=True`:

```python
app.run(host="0.0.0.0", port=3000, debug=True)
```

The **Werkzeug reloader** watches the project's `.py` files and automatically restarts the server as soon as it detects a change: all we have to do is overwrite `app/database.py` and wait a few seconds for the malicious code to be loaded and executed.

### The exploitation chain

1. Build a `.tar.gz` archive containing:
   - a **symlink** entry whose name (sanitized, hence harmless) points, via `linkname` (never filtered), to the application's `app/` directory (a relative path from `app/uploads/`, the extraction folder);
   - a regular file entry whose path **traverses this symlink** and ends with `database.py`, containing a replacement module.
2. Upload this archive via `POST /post_patent` (only "authenticated" by a session name, accessible to anyone).
3. During extraction, `tarfile` creates the symbolic link, then writes the malicious file *through* that link: `app/database.py` gets overwritten on disk.
4. The Flask reloader (`debug=True`) detects the change and restarts the process, loading the malicious `database.py`.
5. The malicious `database.py` redefines `search_comments()` to directly return `os.environ["FLAG"]` instead of fetching a random comment from `bot_outputs`.
6. A simple `GET /comment?name=...` (route `get_comment` → `search_comments()`) then returns the flag as-is, in JSON, without having to wait for / manipulate the bot or the `seed` table.

This is an elegant way to **bypass the entire bot/seed/`bot_outputs` mini-protocol**: instead of computing the exact window the bot exposes (`compute_range`) and hoping to land on the record containing the FLAG, we simply replace the function that reads from the database with one that reads the `FLAG` environment variable.

## The payload (`evil_database.py`)

Minimal module injected in place of `app/database.py`:

```python
import os

def search_comments():
    flag = os.environ.get("FLAG", "404CTF{not_found}")
    return [{"id": 157, "comment": flag}]
```

> Note: the app only needs `search_comments` for the `/comment` route, so a minimal stub is enough (the other functions of the real module — namely `init_db`, `search_patents`, `add_patent`, `add_comment`, `change_seed` — are no longer called once the app is already initialized and the session already open).

## The exploit script (`solver.py`)

`create_session()` opens a session with a random name, `generate_exploit_tar()` builds the archive (symlink `link` → `app-flask/app` plus a malicious `database.py` placed behind that link), `upload_exploit()` sends it via `POST /post_patent`, and `get_flag()` waits for the server to reload (`time.sleep(5)`, retrying if the request hits the server mid-restart) before querying `/comment` and returning the flag directly.

```
$ python3 solver.py
404CTF{...}
```
