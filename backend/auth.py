"""
ŞifrX İstifadəçi Qeydiyyatı və Giriş İdarəetməsi (Auth Manager)
İstifadəçilərin təhlükəsiz qeydiyyatı, yoxlanması və sessiyalarını idarə edir.
Məxfilik: İstifadəçi adları diskdə saxlanılmır (Blind Indexing).
"""

from backend.logging_setup import logged_operation
import logging
logger = logging.getLogger("sifrx.auth")


import secrets
import time
from collections import deque
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timezone
from backend.crypto_engine import CentralCryptoEngine
from backend.storage import CloudStorageManager
from backend.two_factor import verify_second_factor


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
