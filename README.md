Run the backend from the project root:

**Windows (PowerShell):**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r backend/requirements.txt waitress
python -m waitress --host=127.0.0.1 --port=5000 --max-request-body-size=1572864 --inbuf-overflow=2097152 --outbuf-overflow=2097152 --connection-limit=20 --channel-timeout=30 --cleanup-interval=5 backend.app:app
```

For subsequent Windows runs, activate the environment with
`.\.venv\Scripts\Activate.ps1` and run the final command from the project root.

**Linux (Bash):**

```bash
python3 -m venv .venv
source .venv/bin/activate
sudo .venv/bin/python -m pip install -r backend/requirements.txt waitress
sudo .venv/bin/python -m waitress --host=127.0.0.1 --port=5000 --max-request-body-size=1572864 --inbuf-overflow=2097152 --outbuf-overflow=2097152 --connection-limit=20 --channel-timeout=30 --cleanup-interval=5 backend.app:app
```

For subsequent Linux runs, activate the environment with `source .venv/bin/activate`
and run the final command from the project root.

Keep the terminal open while using the API. Frontend files are served separately by Nginx.

# SifrX — Encrypted Vault Storage

**SifrX** stores encrypted vault payloads using a Python API and an HTML/CSS/JavaScript frontend. Encryption and decryption run on the backend: the server receives the master password and plaintext during requests. This architecture is not zero-knowledge or end-to-end encryption. HTTPS is required for network confidentiality. Item titles, types, IDs and timestamps remain plaintext metadata.

---

## 🛡️ Əsas Təhlükəsizlik və Kriptoqrafik Prinsiplər

### 1. Argon2id ilə Master Şifrə Heşlənməsi
Platforma ən müasir beynəlxalq standart olan və Şifrə Heşləmə Yarışmasının (PHC) qalibi seçilən **Argon2id** alqoritmini (RFC 9106 və OWASP tövsiyələri) tətbiq edir:
* Default Argon2id parameters are 64 MiB of memory, two iterations and two lanes. These increase the cost of password guessing; they do not make weak passwords unguessable.
* Password hashes are one-way verifiers. An attacker can still try candidate passwords offline if hashes are exposed.

### 2. Blind Indexing (İstifadəçi Adlarının Anonimləşdirilməsi)
Məxfilik metadata səviyyəsində də qorunur:
* Diskdə və ya bulud saxlancında istifadəçi adları açıq şəkildə qeyd edilmir.
* Hər bir istifadəçinin qovluğu və identifikasiya açarı serverin gizli açarı (**Server Pepper**) ilə **HMAC-SHA256** vasitəsilə birtərəfli anonim heşə çevrilir (`users/<blind_hmac_id>/ in S3`).
* HMAC-derived directory names conceal usernames from a storage-only observer, but do not guarantee anonymity if the pepper or other identifying information is exposed.

### 3. AES-256-GCM encryption
İstifadəçinin bütün login və kart məlumatları **AES-256-GCM** (Galois/Counter Mode) rejimində şifrələnir:
* Hər bir qeyd üçün unikal 128-bitlik kriptoqrafik duz (`salt`) və 96-bitlik təsadüfi `iv` (nonce) generasiya olunur.
* AES-GCM authenticates the ciphertext. Plaintext metadata is not authenticated by the encryption tag.

### 4. Xüsusi `.sifrx` Fayl Konteyneri
Şifrələnmiş məlumatlar diskdə və ya buludda xüsusi `.sifrx` formatında saxlanılır:
```json
{
  "magic": "SIFRX",
  "version": "1.0",
  "cipher": "AES-256-GCM",
  "kdf": "Argon2id",
  "argon2_params": {
    "time_cost": 2,
    "memory_cost": 65536,
    "parallelism": 2
  },
  "salt": "<base64_salt>",
  "iv": "<base64_iv>",
  "tag": "<base64_tag>",
  "ciphertext": "<base64_ciphertext>",
  "meta": {
    "type": "login | card",
    "title": "Məlumat Başlığı",
    "id": "<unikal_uuid>",
    "created_at": "2026-09-28T...",
    "updated_at": "2026-09-28T..."
  }
}
```

### 5. Password handling and security boundaries

The application does not intentionally persist master passwords or decrypted payloads on the backend. They are processed in server memory during API requests. The browser holds the master password in JavaScript memory only; refreshing or navigating to another page requires signing in again. The password is not saved in browser storage. JavaScript cannot guarantee secure memory erasure.

Keep `.env`, `cloud_storage/`, logs and Python caches out of version control. Local files are preserved when removing them from the Git index. Previously committed copies remain in Git history; if that history has been shared, rotate exposed AWS credentials and assess the exposed pepper and account data. Do not replace an existing pepper without a migration: it controls account paths and protects authenticator secrets.

---

## ⚡ Tətbiqin Bütün Funksiyaları

ŞifrX heç bir artıq reklam, marketinq hero bannerləri və ya diqqəti yayındıran elementlər olmadan, sırf işlək və dəqiq funksiyalara köklənmişdir:

### 1. Təhlükəsiz Qeydiyyat və Giriş (Auth)
* **Qeydiyyat Formu:** İstifadəçi adı, master şifrə və şifrə təkrarı daxil edilərək yeni hesab yaradılır. Argon2id verifikatoru generasiya olunur və istifadəçinin anonim bulud qovluğu açılır.
* **Giriş Formu:** Master şifrə yoxlanılır və təhlükəsiz kriptoqrafik sessiya tokeni təyin edilir.
* **Təhlükəsiz Çıxış:** Çıxış düyməsi sıxıldıqda sessiya tokeni və brauzer yaddaşındakı müvəqqəti açarlar dərhal silinir.

### 2. Kriptoqrafik Şifrə Generatoru (Password Generator)
* Kriptoqrafik təsadüfi nömrələr mənbəyindən (CSPRNG — `secrets`) istifadə edir.
* **Uzunluq Nəzarəti:** 8-dən 64 simvola qədər tənzimlənən xüsusi slaydər.
* **Simvol Qrupları:**
  * Böyük hərflər (`A-Z`)
  * Kiçik hərflər (`a-z`)
  * Rəqəmlər (`0-9`)
  * Xüsusi simvollar (`!@#$%^&*()_+-=...`)
* **Kopyalama:** Yaradılan şifrə tək kliklə buferə (clipboard) kopyalanır.
* **Formalara İnteqrasiya:** Login forması daxilində "Yapışdır" düyməsi ilə generasiya olunmuş şifrə avtomatik olaraq müvafiq sahəyə doldurulur.

### 3. Login Məlumatlarının Yaradılması və Saxlanması
* **Sahələr:**
  * Başlıq (məsələn: *Google Hesabı*, *GitHub Pro*, *Dövlət Portalı*)
  * İstifadəçi adı və ya E-poçt
  * Şifrə (məxfi giriş sahəsi)
  * Vebsayt / Qeyd
* Məlumat daxil edilib "Yadda Saxla" düyməsi sıxıldıqda Mərkəzi Şifrələmə Motoru tərəfindən dərhal `.sifrx` formatında şifrələnir və bulud qovluğuna yazılır.

### 4. Bank Kartı Məlumatlarının Yaradılması və Saxlanması
* **Sahələr:**
  * Kart Başlığı (məsələn: *ABB Visa Platinum*, *Kapital BirKart*)
  * Kart Sahibi (Ad və Soyad)
  * 16-rəqəmli Kart Nömrəsi
  * Bitmə Tarixi (`MM/YY`)
  * CVV / CVC (3-rəqəmli gizli kod)
* Kart məlumatları fərdi yaşıl "Kart" nişanı ilə şifrələnmiş şəkildə qorunur.

### 5. Şifrələnmiş Qeydlərə Baxış (Deşifrələmə) və Kopyalama
* Saxlanılmış bütün qeydlər panelin aşağı hissəsində səliqəli siyahı şəklində əks olunur.
* **"Bax" Əməliyyatı:** İstifadəçi "Bax" düyməsinə kliklədikdə Mərkəzi Motor müvafiq `.sifrx` faylını deşifrələyir və məlumatları açır.
* **Tək Kliklə Kopyalama:** Hər bir sahənin (istifadəçi adı, şifrə, kart nömrəsi, CVV və s.) yanında fərdi "Kopyala" düyməsi yerləşir.
* **"Gizlət" Əməliyyatı:** Məlumatla iş bitdikdə təkrar gizlədilir.

### 6. Qeydlərin Silinməsi
* "Sil" düyməsi sıxıldıqda təsdiq pəncərəsi açılır və razılıq verildiyi təqdirdə `.sifrx` faylı istifadəçinin bulud qovluğundan birdəfəlik fiziki olaraq silinir.

---

## 📂 Layihə Strukturu

```text
SifrX/
  backend/
    __init__.py        # Python package marker
    app.py             # WSGI API routes, input checks and request locking
    auth.py            # Sessions, registration, account settings and 2FA
    crypto_engine.py   # Password hashing and vault encryption
    storage.py         # S3-only account storage and rollback
    logging_setup.py   # Single JSON log and operation/request logging
    requirements.txt
  tests/
    test_files.py      # Isolated upload and account-security regressions
    browser_smoke.py   # Real-browser smoke checks with simulated S3
  public/
    html/
      index.html
      settings.html
    css/style.css
    js/
      app.js
      settings.js
  logs/sifrx.json
  README.md
```

Authentication, account settings and two-factor helpers are consolidated in
`backend/auth.py`. Storage, vault encryption, logging and API routing retain
separate modules because they have distinct responsibilities. `__init__.py`
marks `backend` as a regular Python package; it does not start the application.


---

## 🚀 Quraşdırma və Başlatma

### 1. Tələblər
* Python 3.10 və ya daha yuxarı versiya
* `pip` paket meneceri

### 2. Asılılıqların Quraşdırılması
Terminalda layihə qovluğuna keçid edib aşağıdakı əmri icra edin:
```bash
pip install -r backend/requirements.txt
```

### 3. Mühit Konfiqurasiyası (`.env`)
Layihədə dəyişdirilə bilən bütün parametrlər `.env` faylında tənzimlənir:
* **Server:** `FLASK_SECRET_KEY`; HTTP listener settings belong to Nginx.
* **Pepper:** `SIFRX_PEPPER_KEY` is required and must remain stable.
* **Argon2id:** `ARGON2_TIME_COST`, `ARGON2_MEMORY_COST`, `ARGON2_PARALLELISM`.
* **S3:** `AWS_S3_BUCKET` is required. Configure `AWS_REGION`, `AWS_S3_PREFIX`
  and optional `AWS_S3_ENDPOINT_URL`. Credentials use the standard AWS SDK
  chain, including environment variables or IAM roles.

Vault storage is S3-only. Startup fails if configuration is missing or S3 cannot
be reached; runtime failures are reported to callers. Local mirrors, fallback,
account directories and disk staging are removed. `SIFRX_STORAGE_TYPE`,
`SIFRX_LOCAL_STORAGE_PATH` and `SIFRX_STORAGE_PATH` are no longer used.

Before upgrading an installation that used `.server_pepper`, configure
`SIFRX_PEPPER_KEY` with the exact existing key. Binary pepper files require
an explicit migration; generating a replacement changes account prefixes and
prevents decrypting authenticator secrets. Accounts that exist only locally
must be migrated to S3 before using this version. Existing local files remain
untouched and are no longer read by the application.

### 4. Backend application

The backend exports `backend.app:app` as a WSGI application. It does not start
an HTTP server or serve HTML/static files. HTTP serving and deployment are
configured separately. Frontend files are in `public/` and API routes use `/api/`.

Sessions, rate limits and account locks are process-local, so the application
currently requires a single Python worker process.

`HOST`, `PORT` and `FLASK_DEBUG` are no longer backend settings;
`python -m backend.app` no longer starts a listener.

To run the API locally from the project root:

```powershell
python -m pip install waitress
python -m waitress --host=127.0.0.1 --port=5000 --max-request-body-size=1572864 --inbuf-overflow=2097152 --outbuf-overflow=2097152 --connection-limit=20 --channel-timeout=30 --cleanup-interval=5 backend.app:app
```

Keep the process running. Frontend hosting and Nginx configuration are managed
separately. Copy `.env.example` to `.env` only for a new installation; preserve
existing credentials, pepper and storage when updating an existing installation.

### 5. Usage

Open your configured website address in the browser.

1. **"Qeydiyyat"** bölməsinə keçib istifadəçi adı və etibarlı master şifrə ilə qeydiyyatdan keçin.
2. Hesabınıza daxil olun.
3. Şifrə generatorundan istifadə edərək yeni şifrələr yaradın, login və kart məlumatlarınızı `.sifrx` formatında etibarlı şəkildə qoruyun.


## Application logging

When the WSGI application is loaded, logging initializes before storage
and authentication. All categories and error levels are stored once in
`logs/sifrx.json`, a valid JSON array. Existing entries in this file survive
restarts. There are no category files, rotation files or duplicate error copies.
Historical `.jsonl` files are left untouched; new events only go to `sifrx.json`.
Console output is optional. The JSON file grows without automatic rotation.

| Variable | Default | Purpose |
| --- | --- | --- |
| `SIFRX_LOG_LEVEL` | `INFO` | DEBUG, INFO, WARNING, ERROR, CRITICAL |
| `SIFRX_LOG_DIR` | `logs` | Directory containing `sifrx.json` |
| `SIFRX_LOG_CONSOLE` | `true` | Console output toggle |

`SIFRX_LOG_MAX_BYTES` and `SIFRX_LOG_BACKUP_COUNT` are no longer used.
Every event includes a UTC timestamp, level, logger, category and event code.
Request IDs correlate HTTP, authentication, storage, crypto and settings events.
DEBUG adds operation/request start events. Each HTTP response includes
`X-Request-ID`. Browser failures use fixed telemetry event codes.

Passwords, usernames, tokens, cookies, request/response bodies, query strings,
raw URLs, vault titles/content, keys and card information are never logged.
Exception records contain only the exception type and stack locations.
Keep logs private. File writes require the application's single server process;
JSON appends are not crash-atomic. Invalid existing JSON is rejected on startup
rather than silently overwritten.

To read recent events in PowerShell:

```powershell
Get-Content logs/sifrx.json -Raw | ConvertFrom-Json | Select-Object -Last 20
```


## Account settings

Open **Profil ? T?nziml?m?l?r** to access `/settings`.

- **Change password:** enter the current password and confirm the new password.
  Every vault item is re-encrypted, preserving its ID and metadata. All sessions
  are revoked; sign in again with the new password. A corrupt/unreadable item
  aborts the change before any write.
- **Delete account:** enter the current password, type `DELETE`, and confirm.
  Account metadata and vault files are removed from the
  configured S3 account prefix. Other accounts and the server pepper remain.
  S3 version history, provider backups and independent filesystem backups are
  governed by their own retention settings; this action does not purge them.
- **Authenticator 2FA:** enter the current password, scan the QR code or enter
  the setup key in your authenticator app, and confirm its six-digit code.
  Setup expires after five minutes and is not active until confirmed. Save the
  eight one-use recovery codes shown after activation. All sessions are revoked.
  Subsequent logins require the password plus an authenticator or recovery code.
  Enabled 2FA is also required for password changes, deletion and disabling 2FA.
  A TOTP code cannot be reused: wait for the next code after using one.

Install the new dependencies with `python -m pip install -r backend/requirements.txt`
and restart the server. QR codes are generated locally using
[qrcode](https://pypi.org/project/qrcode/); authenticator provisioning uses
[PyOTP](https://pyauth.github.io/pyotp/). There is no external QR service.
Authenticator keys are encrypted at rest using a key derived from the persistent
server pepper; recovery codes are stored only as hashes. Preserve the existing
`SIFRX_PEPPER_KEY` across restarts and deployments.

Security operations require JSON with explicit bearer authentication and reject
cross-site browser requests. Responses are not cached. Password/2FA attempts
are limited to five per account per minute in this server process. Security
operations never silently fall back when configured S3 storage is unavailable.
Account snapshots and rollback data are held in memory; ordinary S3 write
failures restore the previous remote state. This remains a single-process app
with in-memory sessions and request locking; multiple workers/instances need
shared sessions, rate limits and transactions. Multi-object S3 updates are not
crash-atomic. S3 version history and provider backups follow their retention
policies.

Validation:

```powershell
python -m unittest discover -s tests -v
node --check public/js/app.js
node --check public/js/settings.js
```

## Encrypted TXT and CSV files

Choose **Fayl** alongside Login and Kart. Select one `.txt` or `.csv` file and
save it to the encrypted vault. **Bax** displays at most 65,536 characters as
literal text; **Endir** downloads the original bytes, including the original
encoding and BOM; **Sil** deletes the item and frees its quota. Duplicate names
create distinct items. Password changes re-encrypt these files too.

Limits are enforced by the server, independent of browser checks:

| Limit | Value |
| --- | --- |
| Original file bytes | 1,048,576 (1 MiB), inclusive; empty files allowed |
| Uploaded file contents per account | 10,485,760 (10 MiB) |
| Uploaded files per account | 50 |
| Upload JSON body | 1,572,864 bytes, including base64 overhead |
| Other API request bodies | 1,048,576 bytes |
| Stored file package read | 2 MiB |
| Upload attempts | 5/account/minute; 30/server/minute |
| Combined decrypt/download attempts | 20/account/minute, including login/card decrypts |
| Concurrent upload validations | 2 |
| CSV scan | 50,000 rows; 1,024 columns under each supported delimiter |

Text must be strict UTF-8 (optional BOM), or UTF-16 LE/BE with a BOM. Binary
data, NULs and non-text control characters are rejected. CSV is conservatively
scanned under comma, semicolon and tab interpretations using double-quote
escaping. Cells starting with `=`, `+`, `-` or `@`, including hidden-whitespace
and full-width variants, are rejected. This also rejects negative numeric
cells. Files are never imported as records, rendered as HTML, or executed.
Formula rejection reduces risk; it is not a general antivirus scan or a
guarantee about every external spreadsheet application's interpretation.

Uploads use JSON rather than multipart forms. `POST /api/files` requires
`{filename, content_base64, master_password}` and explicit bearer authentication.
File bodies, names, encoding and byte counts are encrypted in `.sifrx` packages
with generated `file_<uuid>` identifiers. Titles (filenames), byte counts,
types, IDs and timestamps remain plaintext metadata. No plaintext files or
public/presigned download URLs are written by the application. The S3 bucket
must remain private. The existing server-side encryption architecture and
single-process requirement still apply; this change is not zero-knowledge.

`GET /api/items` adds an `upload_policy` object with `max_file_bytes`,
`max_total_bytes`, `max_files`, `used_bytes` and `count`. File list entries add
`size_bytes`. Existing `/api/items/<id>/decrypt` returns file preview fields
`filename`, `encoding`, `size_bytes`, `preview` and `truncated`, without base64
content. `POST /api/items/<id>/download` accepts `{master_password}` and returns
an uncached, sandboxed binary attachment. Vault creation, decrypt, download and
deletion now require bearer headers; cookie-only callers must update. Rejected
uploads do not write storage. Size failures return 413, exhausted account quotas
409, and rate/concurrency limits 429 with `Retry-After`.

### Required deployment updates

Install updated requirements and restart the backend using the Waitress command
above or the updated `sifrx.service`. Keep input/output overflow thresholds above
the maximum upload body: Waitress's default 512 KiB input threshold would stage
larger plaintext requests to temporary files. Limits must also be applied at
the reverse proxy, before Waitress buffers any unauthenticated request.

Merge `deploy/nginx-uploads.conf.example` into the existing HTTPS configuration:
put the two rate/concurrency zone declarations in `http {}` and merge the two
locations into the existing website's `server {}`. Preserve existing TLS,
static-file routing and any proxy controls; do not add duplicate locations.
The upload location permits 1536 KiB while other API routes retain 1 MiB. Both
disable request/response disk buffering and use HTTP/1.1 upstream forwarding.
Upload IP limits are 10 requests/minute (burst 2) and 2 concurrent connections;
keep the backend bound to loopback. If another proxy sits before Nginx, configure
its trusted real-client-IP handling explicitly rather than trusting arbitrary
forwarded headers. Run `nginx -t` and reload Nginx after merging the snippet.
These proxy changes are external to this repository and are not applied by
editing the example. Do not enable request-body logging or proxy body caching.

### Isolated verification

`python -m unittest discover -s tests -v` exercises file validation, simulated
S3 storage, quota races, account isolation, rate limits, rollback, rotation and
deletion without using real accounts or cloud data. The existing deletion of
the older authentication test file is preserved.

Optional browser verification uses an ephemeral browser profile and loopback
Waitress with simulated S3. It checks uploads exceeding 512 KiB without server
disk spooling, preview injection, byte-for-byte downloads, CSV rejection,
quota release, existing forms, settings and stale responses after logout:

```powershell
python -m pip install playwright
python tests/browser_smoke.py --channel chrome
```

Use `--channel msedge` for installed Edge. On hosts without an installed browser,
run `python -m playwright install chromium` and omit `--channel`. Playwright is
an optional test dependency and is not needed by the production application.
