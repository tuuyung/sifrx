"""Account security operations, called under the application's request lock."""
import base64
import hashlib
import io
import json
import secrets
import time

import pyotp
import qrcode
from qrcode.image.svg import SvgPathImage

from backend.auth import AuthError
from backend.crypto_engine import CentralCryptoEngine
from backend.logging_setup import logged_operation
from backend.two_factor import matching_counter, seal_secret, verify_second_factor


class AccountSettings:
    def __init__(self, auth):
        self.auth = auth
        self.storage = auth.storage
        self.pending = {}

    def _load(self, username):
        snapshot = self.storage.account_snapshot(username)
        files = {**snapshot[1], **snapshot[0]}
        if "user.meta" not in files:
            raise AuthError("Hesab tapılmadı.")
        return snapshot, files, json.loads(files["user.meta"])

    def _authorize(self, username, password, code):
        self.auth.check_rate_limit(username)
        snapshot, files, meta = self._load(username)
        if not CentralCryptoEngine.verify_auth_verifier(password, base64.b64decode(meta["salt"]), meta["verifier"]):
            raise AuthError("Cari şifrə yanlışdır.")
        updated = verify_second_factor(meta, code, self.storage.pepper_key,
                                       self.storage.compute_blind_index(username))
        if updated is None:
            raise AuthError("Etibarlı 2FA və ya bərpa kodu tələb olunur.")
        return snapshot, files, updated

    def _save(self, username, files, meta, snapshot):
        files["user.meta"] = json.dumps(meta, ensure_ascii=False).encode("utf-8")
        try:
            self.storage.replace_account(username, files, snapshot)
        except Exception as error:
            if getattr(error, "committed", False):
                self.auth.revoke_sessions(username)
            raise
        self.auth.clear_attempts(username)

    def status(self, username):
        _, _, meta = self._load(username)
        return {"username": username, "two_factor_enabled": bool(meta.get("two_factor", {}).get("enabled"))}

    @logged_operation
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
        salt = CentralCryptoEngine.generate_salt()
        meta["salt"] = base64.b64encode(salt).decode("ascii")
        meta["verifier"] = CentralCryptoEngine.compute_auth_verifier(new_password, salt)
        self._save(username, files, meta, snapshot)
        self.auth.revoke_sessions(username)
        self.pending.pop(self.storage.compute_blind_index(username), None)

    @logged_operation
    def delete_account(self, username, password, code, confirmation):
        if confirmation != "DELETE":
            raise AuthError("Təsdiq üçün DELETE yazın.")
        snapshot, _, _ = self._authorize(username, password, code)
        try:
            self.storage.replace_account(username, None, snapshot)
        except Exception as error:
            if getattr(error, "committed", False):
                self.auth.revoke_sessions(username)
            raise
        self.auth.revoke_sessions(username)
        self.pending.pop(self.storage.compute_blind_index(username), None)
        self.auth.clear_attempts(username)

    @logged_operation
    def begin_two_factor(self, username, password, session_token):
        snapshot, files, meta = self._authorize(username, password, "")
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

    @logged_operation
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
                              "recovery_codes": [hashlib.sha256(code.encode()).hexdigest() for code in codes]}
        self._save(username, files, meta, snapshot)
        del self.pending[account_id]
        self.auth.revoke_sessions(username)
        return codes

    @logged_operation
    def disable_two_factor(self, username, password, code):
        snapshot, files, meta = self._authorize(username, password, code)
        meta.pop("two_factor", None)
        self._save(username, files, meta, snapshot)
        self.auth.revoke_sessions(username)
