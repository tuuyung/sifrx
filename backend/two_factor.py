"""Authenticator secrets are encrypted using the persistent server pepper."""
import base64
import hashlib
import hmac
import secrets
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pyotp


def seal_secret(secret, pepper, account_id):
    key = hmac.new(pepper, b"sifrx:totp-encryption:v1", hashlib.sha256).digest()
    nonce = secrets.token_bytes(12)
    value = AESGCM(key).encrypt(nonce, secret.encode("ascii"), account_id.encode("ascii"))
    return base64.b64encode(nonce + value).decode("ascii")


def open_secret(value, pepper, account_id):
    key = hmac.new(pepper, b"sifrx:totp-encryption:v1", hashlib.sha256).digest()
    raw = base64.b64decode(value)
    return AESGCM(key).decrypt(raw[:12], raw[12:], account_id.encode("ascii")).decode("ascii")


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
        digest = hashlib.sha256(str(code or "").strip().replace("-", "").upper().encode()).hexdigest()
        codes = list(config.get("recovery_codes", []))
        match = next((item for item in codes if hmac.compare_digest(item, digest)), None)
        if match is None:
            return None
        codes.remove(match)
        config["recovery_codes"] = codes
    updated["two_factor"] = config
    return updated
