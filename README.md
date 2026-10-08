Run the backend from the project root:

```powershell
python -m pip install -r backend/requirements.txt waitress
python -m waitress --host=127.0.0.1 --port=5000 backend.app:app
```

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
* Hər bir istifadəçinin qovluğu və identifikasiya açarı serverin gizli açarı (**Server Pepper**) ilə **HMAC-SHA256** vasitəsilə birtərəfli anonim heşə çevrilir (`cloud_storage/users/<blind_hmac_id>/`).
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

```
ŞifrX/
│
├── backend/
│   ├── crypto_engine.py      # MƏRKƏZİ ŞİFRƏLƏMƏ MOTORU (Argon2id, AES-256-GCM, .sifrx format, generator)
│   ├── storage.py            # BULUD SAXLANC MENECERİ (Blind Indexing HMAC-SHA256, .sifrx idarəsi)
│   ├── auth.py               # AUTENTİFİKASİYA MENECERİ (Qeydiyyat, giriş, təhlükəsiz sessiyalar)
│   ├── app.py                # WSGI REST API behind Nginx
│   ├── account_settings.py
│   ├── logging_setup.py
│   ├── two_factor.py
│   ├── requirements.txt      # Python asılılıqları (Flask, cryptography, argon2-cffi)
│   └── tests/
├── README.md             # Tətbiqin tam təlimat və arxitektura sənədi
│
├── public/
│   ├── html/
│   │   ├── index.html    # Təmiz, izahsız, ultra-minimalist HTML interfeys
│   │   └── settings.html
│   ├── css/
│   │   └── style.css     # Müasir tünd minimalist dizayn sistemi
│   └── js/
│       └── app.js        # Çevik vanilla JavaScript nəzarətçisi
│
└── cloud_storage/        # BULUD YADDAŞI QOVLUĞU
    ├── .server_pepper    # Serverin gizli pepper açarı (anonimləşdirmə üçün)
    └── users/            # İstifadəçilərin anonim heşlənmiş qovluqları
        └── <blind_id>/   # Məs: 349a8a25f64a20dc86ae1aecf382bfbc...
            ├── user.meta # Argon2id verifikatoru (açıq istifadəçi adı saxlanılmır)
            └── *.sifrx   # Şifrələnmiş login və kart məlumatları
```

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
* **Server Parametrləri:** `FLASK_SECRET_KEY` (HTTP listener settings belong to Nginx).
* **Məxfilik (Pepper):** `SIFRX_PEPPER_KEY` (boş qaldıqda avtomatik `.server_pepper` faylından istifadə olunur).
* **Argon2id:** `ARGON2_TIME_COST`, `ARGON2_MEMORY_COST`, `ARGON2_PARALLELISM`.
* **Amazon S3 və Ağıllı Fallback:**
  ```env
  AWS_ACCESS_KEY_ID=sizin_access_key
  AWS_SECRET_ACCESS_KEY=sizin_secret_key
  AWS_REGION=us-east-1
  AWS_S3_BUCKET=sizin_bucket_adi
  AWS_S3_ENDPOINT_URL= # İxtiyari (Cloudflare R2, MinIO və s. üçün)
  ```
  Configured S3 write failures are reported to the client; uploads and deletes
  do not silently succeed with only a local copy. Explicit local-only development
  uses `SIFRX_STORAGE_TYPE=local`. Keep the persistent pepper backed up privately.

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
python -m waitress --host=127.0.0.1 --port=5000 backend.app:app
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
and authentication. JSON events are written to category-specific files and the
console. Each file rotates independently at 5 MiB with five backups. No additional
logging dependencies are needed.

| File in `logs/` | Category |
| --- | --- |
| `requests.jsonl` | HTTP requests, response status, timing and API failures |
| `authentication.jsonl` | Registration, login, session lookup and revocation |
| `storage.jsonl` | Local/S3 operations, fallback and recovery |
| `crypto.jsonl` | Encryption, decryption, password generation and verification |
| `settings.jsonl` | Password changes, account deletion and 2FA management |
| `frontend.jsonl` | Browser activity, network, clipboard and browser errors |
| `application.jsonl` | Startup, runtime and uncategorized application events |
| `errors.jsonl` | An additional copy of ERROR and CRITICAL events from all categories |

Every event includes its `category`. Domain events appear in one category file;
errors also appear in `errors.jsonl`. Request IDs are shared across category files
so related authentication, storage, crypto and settings events can be traced.
The previous `sifrx.jsonl` file, if present, is retained as historical output;
new events go to the files above after the server restarts.

Set these variables in `.env` to customize logging:

| Variable | Default | Purpose |
| --- | --- | --- |
| `SIFRX_LOG_LEVEL` | `INFO` | DEBUG, INFO, WARNING, ERROR, CRITICAL |
| `SIFRX_LOG_DIR` | `logs` | Log directory |
| `SIFRX_LOG_MAX_BYTES` | `5242880` | Rotation size in bytes per file |
| `SIFRX_LOG_BACKUP_COUNT` | `5` | Retained rotated files per category |
| `SIFRX_LOG_CONSOLE` | `true` | Console output toggle |

Logs cover HTTP status and duration, authentication/session operations, storage
operations and recovery/fallback paths, cryptographic operations, browser actions,
network failures, uncaught browser errors and clipboard failures. DEBUG adds
operation/request start events. Each HTTP response includes `X-Request-ID` to
correlate events. Timestamps use UTC.

Passwords, usernames, tokens, cookies, request/response bodies, query strings,
raw URLs, vault titles/content, keys and card information are never logged.
Exception records contain the exception type and stack locations, excluding
exception messages, source text and local variables. Browser telemetry sends
fixed event codes only (no error text or clicked element content), with a
30-events/minute browser limit and a 60-events/minute server limit per process.
Server request logs still record rejected telemetry requests. Logs are local;
no external logging service is used. Keep the log directory private. Rotation
is intended for a single server process; use a centralized collector for a
multi-process deployment.

To follow logs in PowerShell:

```powershell
Get-Content logs/requests.jsonl -Wait -Tail 20
Get-Content logs/errors.jsonl -Wait -Tail 20
```


## Account settings

Open **Profil ? T?nziml?m?l?r** to access `/settings`.

- **Change password:** enter the current password and confirm the new password.
  Every vault item is re-encrypted, preserving its ID and metadata. All sessions
  are revoked; sign in again with the new password. A corrupt/unreadable item
  aborts the change before any write.
- **Delete account:** enter the current password, type `DELETE`, and confirm.
  Account metadata and vault files are removed from local storage and the
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
`SIFRX_PEPPER_KEY` or `cloud_storage/.server_pepper`, including across restarts.

Security operations require JSON with explicit bearer authentication and reject
cross-site browser requests. Responses are not cached. Password/2FA attempts
are limited to five per account per minute in this server process. Security
operations never silently fall back when configured S3 storage is unavailable.
Local changes are staged and ordinary write failures roll back local/S3 state.
This remains a single-process app with in-memory sessions and request locking;
multiple workers/instances need shared sessions, rate limits and transactions.
Filesystem/S3 updates are not a distributed crash-atomic transaction: preserve
backups and investigate `.account-stage-*` / `.account-backup-*` directories if
an operation is interrupted by a server or machine crash. Existing independent
backups must follow your retention policy.

Validation:

```powershell
python -m unittest discover -s backend/tests -v
node --check public/js/app.js
node --check public/js/settings.js
node public/js/tests/security.test.cjs
```
