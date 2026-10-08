"""Authentication, account security settings and authenticator verification.

The API serializes account operations using its request lock. Sessions, rate
limits and pending authenticator setup are held in process memory.
"""

import base64
import hashlib
import hmac
import io
import json
import secrets
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pyotp
import qrcode
from qrcode.image.svg import SvgPathImage

from backend.crypto_engine import CentralCryptoEngine
from backend.logging_setup import logged_operation
from backend.storage import CloudStorageManager


def _authenticator_key(pepper):
    return hmac.new(pepper, b"sifrx:totp-encryption:v1", hashlib.sha256).digest()


def seal_secret(secret, pepper, account_id):
    nonce = secrets.token_bytes(12)
    value = AESGCM(_authenticator_key(pepper)).encrypt(nonce, secret.encode("ascii"), account_id.encode("ascii"))
    return base64.b64encode(nonce + value).decode("ascii")


def open_secret(value, pepper, account_id):
    raw = base64.b64decode(value)
    return AESGCM(_authenticator_key(pepper)).decrypt(raw[:12], raw[12:], account_id.encode("ascii")).decode("ascii")


def _recovery_code_digest(code):
    normalized = str(code or "").strip().replace("-", "").upper()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def matching_counter(secret, code, last_counter=-1):
    if not isinstance(code, str) or len(code) != 6 or not code.isascii() or not code.isdigit():
        return None
    now = int(time.time()) // 30
    totp = pyotp.TOTP(secret)
    for counter in (now, now - 1, now + 1):
        if counter > last_counter and hmac.compare_digest(totp.at(counter * 30), code):
            return counter
    return None


def verify_second_factor(meta, code, pepper, account_id):
    """Return updated metadata after one-use TOTP or recovery-code validation."""
    updated = dict(meta)
    config = dict(meta.get("two_factor", {}))
    if not config.get("enabled"):
        return updated
    secret = open_secret(config["secret"], pepper, account_id)
    counter = matching_counter(secret, code, config.get("last_counter", -1))
    if counter is not None:
        config["last_counter"] = counter
    else:
        digest = _recovery_code_digest(code)
        codes = list(config.get("recovery_codes", []))
        match = next((item for item in codes if hmac.compare_digest(item, digest)), None)
        if match is None:
            return None
        codes.remove(match)
        config["recovery_codes"] = codes
    updated["two_factor"] = config
    return updated


class AuthError(Exception):
    """Autentifikasiya xətası."""
    pass


class TwoFactorRequired(AuthError):
    pass


class RateLimitError(AuthError):
    pass


class AuthManager:
    """İstifadəçi qeydiyyatı, giriş və sessiya idarəçisi."""

    @logged_operation
    def __init__(self, storage_manager: CloudStorageManager):
        self.storage = storage_manager
        # Sadə və təhlükəsiz yaddaş-əsaslı sessiya anbarı: {token: {"username": str, "login_time": iso}}
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._attempts = {}

    def check_rate_limit(self, username):
        now = time.monotonic()
        self._attempts = {key: times for key, times in self._attempts.items()
                          if times and times[-1] > now - 60}
        key = self.storage.compute_blind_index(username)
        attempts = self._attempts.setdefault(key, deque())
        while attempts and attempts[0] <= now - 60:
            attempts.popleft()
        if len(attempts) >= 5 or len(self._attempts) > 10000:
            raise RateLimitError("Çox sayda cəhd edildi. Bir dəqiqə sonra yenidən cəhd edin.")
        attempts.append(now)

    def clear_attempts(self, username):
        self._attempts.pop(self.storage.compute_blind_index(username), None)

    def verify_account_second_factor(self, username, meta, code):
        """Share account-specific second-factor validation with settings."""
        return verify_second_factor(meta, code, self.storage.pepper_key,
                                    self.storage.compute_blind_index(username))

    @logged_operation
    def revoke_sessions(self, username):
        account_id = self.storage.compute_blind_index(username)
        self._sessions = {token: session for token, session in self._sessions.items()
                          if self.storage.compute_blind_index(session["username"]) != account_id}

    @logged_operation
    def register(self, username: str, password: str, confirm_password: str) -> Dict[str, Any]:
        """Yeni istifadəçi qeydiyyatı."""
        username = username.strip()
        if len(username) < 3:
            raise AuthError("İstifadəçi adı ən azı 3 simvol olmalıdır.")
        if len(password) < 6:
            raise AuthError("Master şifrə ən azı 6 simvol olmalıdır.")
        if password != confirm_password:
            raise AuthError("Şifrələr uyğun gəlmir.")

        if self.storage.user_exists(username):
            raise AuthError("Bu istifadəçi adı artıq qeydiyyatdan keçib.")

        # Duz (salt) və Argon2id verifikatorunun generasiyası
        meta = {
            **CentralCryptoEngine.create_auth_credentials(password),
            "created_at": datetime.now(timezone.utc).isoformat()
        }

        # İstifadəçi üçün anonim bulud qovluğu açılır və meta fayl yazılır
        self.storage.save_user_meta(username, meta)

        return {"success": True, "username": username}

    @logged_operation
    def login(self, username: str, password: str, otp_code: str = "") -> Tuple[str, Dict[str, Any]]:
        """İstifadəçi girişi və sessiya tokeninin yaradılması."""
        username = username.strip()
        if not username or not password:
            raise AuthError("İstifadəçi adı və şifrə tələb olunur.")

        self.check_rate_limit(username)
        snapshot, files, user_meta = self.storage.load_account(username)
        if not user_meta:
            raise AuthError("İstifadəçi adı və ya şifrə yanlışdır.")

        if not CentralCryptoEngine.verify_account_password(password, user_meta):
            raise AuthError("İstifadəçi adı və ya şifrə yanlışdır.")

        if user_meta.get("two_factor", {}).get("enabled"):
            if not otp_code:
                # The password was verified, but no authenticated session is issued yet.
                raise TwoFactorRequired("Authenticator tətbiqindən kodu daxil edin.")
            updated = self.verify_account_second_factor(username, user_meta, otp_code)
            if updated is None:
                raise TwoFactorRequired("2FA kodu yanlışdır, vaxtı bitib və ya artıq istifadə olunub.")
            self.storage.save_account_meta(username, files, updated, snapshot)
        self.clear_attempts(username)

        # Uğurlu giriş: Təhlükəsiz sessiya tokeni yaradılır
        token = secrets.token_hex(32)
        self._sessions[token] = {
            "username": username,
            "login_time": datetime.now(timezone.utc).isoformat()
        }

        return token, {"username": username}

    @logged_operation
    def get_session_user(self, token: Optional[str]) -> Optional[str]:
        """Tokenə əsasən cari istifadəçi adını qaytarır."""
        if not token:
            return None
        sess = self._sessions.get(token)
        if sess:
            return sess.get("username")
        return None

    @logged_operation
    def logout(self, token: Optional[str]) -> bool:
        """Sessiyanı sonlandırır."""
        if token and token in self._sessions:
            del self._sessions[token]
            return True
        return False


class AccountSettings:
    def __init__(self, auth):
        self.auth = auth
        self.storage = auth.storage
        self.pending = {}

    def _load(self, username):
        snapshot, files, meta = self.storage.load_account(username)
        if meta is None:
            raise AuthError("Hesab tapılmadı.")
        return snapshot, files, meta

    def _authorize(self, username, password, code):
        self.auth.check_rate_limit(username)
        snapshot, files, meta = self._load(username)
        if not CentralCryptoEngine.verify_account_password(password, meta):
            raise AuthError("Cari şifrə yanlışdır.")
        updated = self.auth.verify_account_second_factor(username, meta, code)
        if updated is None:
            raise AuthError("Etibarlı 2FA və ya bərpa kodu tələb olunur.")
        return snapshot, files, updated

    def _save(self, username, files, meta, snapshot):
        self.storage.save_account_meta(username, files, meta, snapshot)

    def _finish_security_change(self, username):
        """Invalidate sessions and pending setup only after a successful commit."""
        self.auth.revoke_sessions(username)
        self.pending.pop(self.storage.compute_blind_index(username), None)
        self.auth.clear_attempts(username)

    def status(self, username):
        _, _, meta = self._load(username)
        return {"username": username, "two_factor_enabled": bool(meta.get("two_factor", {}).get("enabled"))}

    @logged_operation(logger_name="account_settings")
    def change_password(self, username, current_password, new_password, confirmation, code):
        if len(new_password) < 6:
            raise AuthError("Yeni şifrə ən azı 6 simvol olmalıdır.")
        if new_password != confirmation:
            raise AuthError("Yeni şifrələr uyğun gəlmir.")
        if new_password == current_password:
            raise AuthError("Yeni şifrə cari şifrədən fərqli olmalıdır.")
        snapshot, files, meta = self._authorize(username, current_password, code)
        # Decrypt and stage every item before writing anything. Corruption aborts safely.
        for name, content in list(files.items()):
            if name.endswith(".sifrx"):
                original = json.loads(content)
                item = CentralCryptoEngine.decrypt_from_sifrx(original, current_password)
                encrypted = CentralCryptoEngine.encrypt_to_sifrx(item["payload"], new_password, meta=item["meta"])
                files[name] = json.dumps(encrypted, ensure_ascii=False).encode("utf-8")
        meta.update(CentralCryptoEngine.create_auth_credentials(new_password))
        self._save(username, files, meta, snapshot)
        self._finish_security_change(username)

    @logged_operation(logger_name="account_settings")
    def delete_account(self, username, password, code, confirmation):
        if confirmation != "DELETE":
            raise AuthError("Təsdiq üçün DELETE yazın.")
        snapshot, _, _ = self._authorize(username, password, code)
        self.storage.replace_account(username, None, snapshot)
        self._finish_security_change(username)

    @logged_operation(logger_name="account_settings")
    def begin_two_factor(self, username, password, session_token):
        _, _, meta = self._authorize(username, password, "")
        if meta.get("two_factor", {}).get("enabled"):
            raise AuthError("2FA artıq aktivdir.")
        self.pending = {key: value for key, value in self.pending.items() if value["expires"] > time.monotonic()}
        secret = pyotp.random_base32()
        account_id = self.storage.compute_blind_index(username)
        self.pending[account_id] = {"secret": secret, "expires": time.monotonic() + 300, "session": session_token}
        uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="SifrX")
        image = qrcode.make(uri, image_factory=SvgPathImage, box_size=6, border=4)
        buffer = io.BytesIO()
        image.save(buffer)
        self.auth.clear_attempts(username)
        return {"secret": secret, "qr_code": "data:image/svg+xml;base64," + base64.b64encode(buffer.getvalue()).decode("ascii"),
                "expires_in": 300}

    @logged_operation(logger_name="account_settings")
    def enable_two_factor(self, username, password, code, session_token):
        snapshot, files, meta = self._authorize(username, password, "")
        account_id = self.storage.compute_blind_index(username)
        pending = self.pending.get(account_id)
        if not pending or pending["expires"] < time.monotonic() or pending["session"] != session_token:
            raise AuthError("Quraşdırmanın vaxtı bitib. Yenidən başlayın.")
        counter = matching_counter(pending["secret"], code)
        if counter is None:
            raise AuthError("Authenticator kodu yanlışdır.")
        codes = [secrets.token_hex(8).upper() for _ in range(8)]
        meta["two_factor"] = {"enabled": True,
                              "secret": seal_secret(pending["secret"], self.storage.pepper_key, account_id),
                              "last_counter": counter,
                              "recovery_codes": [_recovery_code_digest(code) for code in codes]}
        self._save(username, files, meta, snapshot)
        self._finish_security_change(username)
        return codes

    @logged_operation(logger_name="account_settings")
    def disable_two_factor(self, username, password, code):
        snapshot, files, meta = self._authorize(username, password, code)
        meta.pop("two_factor", None)
        self._save(username, files, meta, snapshot)
        self._finish_security_change(username)
