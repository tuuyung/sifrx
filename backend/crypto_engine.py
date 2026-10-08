"""
ŞifrX Mərkəzi Şifrələmə Motoru (Central Cryptographic Engine)
Bütün kriptoqrafik əməliyyatlar (Argon2id heşləməsi və açar törədilməsi,
AES-256-GCM şifrələmə/deşifrələmə, .sifrx formatının formalaşdırılması və şifrə generasiyası)
bu modul vasitəsilə icra olunur.
"""

from backend.logging_setup import logged_operation
import logging
logger = logging.getLogger("sifrx.crypto_engine")


import os
import json
import base64
import secrets
import string
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import hmac
from dotenv import load_dotenv

load_dotenv()

try:
    from argon2 import PasswordHasher
    from argon2.low_level import hash_secret_raw, Type
    from argon2.exceptions import VerifyMismatchError, VerificationError
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False


class CryptoError(Exception):
    """Kriptoqrafik əməliyyat xətası."""
    pass


class InvalidKeyOrTamperedDataError(CryptoError):
    """Yanlış şifrə və ya zədələnmiş/dəyişdirilmiş məlumat xətası."""
    pass


class CentralCryptoEngine:
    """
    SifrX Mərkəzi Şifrələmə Motoru
    Bütün şifrələmə və açar idarəetməsi mərkəzləşdirilmiş şəkildə buradadır.
    Master şifrənin heşlənməsi və açar törədilməsi Argon2id alqoritmi ilə həyata keçirilir.
    """
    MAGIC = "SIFRX"
    VERSION = "1.0"
    CIPHER = "AES-256-GCM"
    KDF_ALGO = "Argon2id"
    
    # Argon2id Parametrləri (OWASP və RFC 9106 standartı)
    ARGON2_TIME_COST = 2       # İterasiya sayı
    ARGON2_MEMORY_COST = 65536 # 64 MB operativ yaddaş (GPU hücumlarına qarşı qorunma)
    ARGON2_PARALLELISM = 2     # Paralel axın sayı
    
    KEY_LENGTH_BYTES = 32      # 256 bit AES açarı
    IV_LENGTH_BYTES = 12       # 96 bit (GCM üçün tövsiyə olunan standart)
    SALT_LENGTH_BYTES = 16     # 128 bit təsadüfi duz

    # Geriye uyğunluq üçün PBKDF2 iterasiyası
    LEGACY_PBKDF2_ITERATIONS = 200_000

    @classmethod
    @logged_operation
    def get_argon2_params(cls):
        """Mühitdən (.env) və ya defolt Argon2 parametrlərini qaytarır."""
        try:
            tc = int(os.environ.get("ARGON2_TIME_COST", cls.ARGON2_TIME_COST))
            mc = int(os.environ.get("ARGON2_MEMORY_COST", cls.ARGON2_MEMORY_COST))
            p = int(os.environ.get("ARGON2_PARALLELISM", cls.ARGON2_PARALLELISM))
            return tc, mc, p
        except Exception:
            logger.warning("CentralCryptoEngine.get_argon2_params.recovery", exc_info=True)
            return cls.ARGON2_TIME_COST, cls.ARGON2_MEMORY_COST, cls.ARGON2_PARALLELISM

    @classmethod
    @logged_operation
    def get_password_hasher(cls) -> "PasswordHasher":
        """Argon2id PasswordHasher instansiyasını qaytarır."""
        tc, mc, p = cls.get_argon2_params()
        return PasswordHasher(
            time_cost=tc,
            memory_cost=mc,
            parallelism=p,
            hash_len=cls.KEY_LENGTH_BYTES,
            type=Type.ID
        )

    @classmethod
    @logged_operation
    def generate_salt(cls) -> bytes:
        """Kriptoqrafik təsadüfi duz (salt) yaradır."""
        return os.urandom(cls.SALT_LENGTH_BYTES)

    @classmethod
    def create_auth_credentials(cls, password):
        """Create the persisted salt/verifier pair for registration or rotation."""
        salt = cls.generate_salt()
        return {
            "salt": base64.b64encode(salt).decode("ascii"),
            "verifier": cls.compute_auth_verifier(password, salt),
        }

    @classmethod
    def verify_account_password(cls, password, meta):
        """Verify a password against the credentials stored in account metadata."""
        return cls.verify_auth_verifier(password, base64.b64decode(meta["salt"]), meta["verifier"])

    @classmethod
    @logged_operation
    def compute_auth_verifier(cls, master_password: str, salt: Optional[bytes] = None) -> str:
        """
        Master şifrəni diskdə saxlamamaq üçün Argon2id ilə heşləyir.
        Nəticə standart PHC formatında qaytarılır ($argon2id$v=19$m=65536,t=2,p=2$...).
        """
        if not master_password:
            raise CryptoError("Master şifrə boş ola bilməz.")
        
        if ARGON2_AVAILABLE:
            ph = cls.get_password_hasher()
            return ph.hash(master_password)
        else:
            # Əgər hər hansı səbəbdən argon2 mövcud olmasa, fallback PBKDF2
            if not salt:
                salt = cls.generate_salt()
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100_000,
            )
            verifier_bytes = kdf.derive(master_password.encode("utf-8") + b"::sifrx-auth-verifier")
            return base64.b64encode(verifier_bytes).decode("ascii")

    @classmethod
    @logged_operation
    def verify_auth_verifier(cls, candidate_password: str, salt: bytes, expected_verifier: str) -> bool:
        """
        İstifadəçinin daxil etdiyi şifrənin doğruluğunu Argon2id heşi ilə yoxlayır.
        Əvvəlki PBKDF2 heşləri ilə geriyə uyğunluğu da qoruyur.
        """
        if not candidate_password or not expected_verifier:
            return False

        # 1. Argon2 heşi yoxlanışı
        if expected_verifier.startswith("$argon2"):
            if not ARGON2_AVAILABLE:
                return False
            try:
                ph = cls.get_password_hasher()
                return ph.verify(expected_verifier, candidate_password)
            except (VerifyMismatchError, VerificationError):
                logger.warning("CentralCryptoEngine.verify_auth_verifier.recovery", exc_info=True)
                return False
            except Exception:
                logger.warning("CentralCryptoEngine.verify_auth_verifier.recovery", exc_info=True)
                return False

        # 2. Əvvəlki PBKDF2 heşi ilə fallback yoxlanışı
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100_000,
            )
            verifier_bytes = kdf.derive(candidate_password.encode("utf-8") + b"::sifrx-auth-verifier")
            computed = base64.b64encode(verifier_bytes).decode("ascii")
            return hmac.compare_digest(computed, expected_verifier)
        except Exception:
            logger.warning("CentralCryptoEngine.verify_auth_verifier.recovery", exc_info=True)
            return False

    @classmethod
    @logged_operation
    def derive_key(
        cls,
        master_password: str,
        salt: bytes,
        kdf_algo: str = "Argon2id",
        iterations: Optional[int] = None,
        argon2_params: Optional[Dict[str, int]] = None
    ) -> bytes:
        """
        Master şifrədən və duzdan 256-bitlik AES açarı törədir.
        Standart olaraq Argon2id istifadə olunur, köhnə fayllar üçün PBKDF2 dəstəklənir.
        """
        if not master_password:
            raise CryptoError("Master şifrə boş ola bilməz.")

        if kdf_algo == "Argon2id":
            if not ARGON2_AVAILABLE:
                raise CryptoError("Argon2id dependency is required.")
            if argon2_params is None:
                tc, mc, p = cls.get_argon2_params()
            else:
                if not isinstance(argon2_params, dict):
                    raise CryptoError("Invalid Argon2id parameters.")
                tc, mc, p = (argon2_params.get(name) for name in
                             ("time_cost", "memory_cost", "parallelism"))
                if (any(type(value) is not int for value in (tc, mc, p))
                        or not 1 <= tc <= 20 or not 1 <= p <= 32
                        or not 8 * p <= mc <= 262144):
                    raise CryptoError("Invalid Argon2id parameters.")
            return hash_secret_raw(
                secret=master_password.encode("utf-8"),
                salt=salt,
                time_cost=tc,
                memory_cost=mc,
                parallelism=p,
                hash_len=cls.KEY_LENGTH_BYTES,
                type=Type.ID
            )
        elif kdf_algo == "PBKDF2-HMAC-SHA256":
            # PBKDF2-HMAC-SHA256
            if iterations is None:
                iterations = cls.LEGACY_PBKDF2_ITERATIONS
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=cls.KEY_LENGTH_BYTES,
                salt=salt,
                iterations=iterations,
            )
            return kdf.derive(master_password.encode("utf-8"))
        else:
            raise CryptoError("Unsupported key derivation algorithm.")

    @classmethod
    @logged_operation
    def encrypt_to_sifrx(cls, payload: Dict[str, Any], master_password: str, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        İstifadəçinin JSON məlumatını Argon2id ilə törədilmiş açar və AES-256-GCM ilə şifrələyir,
        standart .sifrx formatlı paketə çevirir.
        """
        try:
            salt = cls.generate_salt()
            key = cls.derive_key(master_password, salt, kdf_algo="Argon2id")
            iv = os.urandom(cls.IV_LENGTH_BYTES)

            plaintext_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")

            aesgcm = AESGCM(key)
            encrypted_data = aesgcm.encrypt(iv, plaintext_bytes, None)

            # cryptography kitabxanasında GCM son 16 baytı tag edir
            ciphertext = encrypted_data[:-16]
            tag = encrypted_data[-16:]

            tc, mc, p = cls.get_argon2_params()
            sifrx_package = {
                "magic": cls.MAGIC,
                "version": cls.VERSION,
                "cipher": cls.CIPHER,
                "kdf": "Argon2id",
                "argon2_params": {
                    "time_cost": tc,
                    "memory_cost": mc,
                    "parallelism": p
                },
                "salt": base64.b64encode(salt).decode("ascii"),
                "iv": base64.b64encode(iv).decode("ascii"),
                "tag": base64.b64encode(tag).decode("ascii"),
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
                "meta": meta or {}
            }
            return sifrx_package
        except Exception as e:
            logger.warning("CentralCryptoEngine.encrypt_to_sifrx.recovery", exc_info=True)
            raise CryptoError(f"Şifrələmə zamanı xəta baş verdi: {str(e)}")

    @classmethod
    @logged_operation
    def decrypt_from_sifrx(cls, sifrx_package: Any, master_password: str) -> Dict[str, Any]:
        """
        .sifrx formatlı paketi qəbul edir, bütövlüyünü yoxlayır və
        master şifrə ilə deşifrələyərək əsl JSON məlumatını qaytarır.
        Həm yeni Argon2id, həm də köhnə PBKDF2 .sifrx fayllarını deşifrələyir.
        """
        try:
            if isinstance(sifrx_package, str):
                sifrx_package = json.loads(sifrx_package)

            if sifrx_package.get("magic") != cls.MAGIC:
                raise CryptoError("Fayl formatı düzgün deyil (SIFRX başlığı yoxdur).")

            salt = base64.b64decode(sifrx_package["salt"])
            iv = base64.b64decode(sifrx_package["iv"])
            tag = base64.b64decode(sifrx_package["tag"])
            ciphertext = base64.b64decode(sifrx_package["ciphertext"])

            kdf_algo = sifrx_package.get("kdf", "PBKDF2-HMAC-SHA256")
            iterations = sifrx_package.get("iterations", cls.LEGACY_PBKDF2_ITERATIONS)

            key = cls.derive_key(master_password, salt, kdf_algo=kdf_algo,
                                 iterations=iterations,
                                 argon2_params=sifrx_package.get("argon2_params"))
            aesgcm = AESGCM(key)

            encrypted_data = ciphertext + tag
            decrypted_bytes = aesgcm.decrypt(iv, encrypted_data, None)
            payload = json.loads(decrypted_bytes.decode("utf-8"))

            return {
                "payload": payload,
                "meta": sifrx_package.get("meta", {})
            }
        except Exception as e:
            logger.warning("CentralCryptoEngine.decrypt_from_sifrx.recovery", exc_info=True)
            raise InvalidKeyOrTamperedDataError(
                "Məlumatı deşifrələmək mümkün olmadı. Master şifrə yanlışdır və ya məlumat zədələnib."
            )

    @classmethod
    @logged_operation
    def generate_password(
        cls,
        length: int = 16,
        use_upper: bool = True,
        use_lower: bool = True,
        use_digits: bool = True,
        use_symbols: bool = True
    ) -> str:
        """
        Kriptoqrafik təsadüfi (CSPRNG) güclü şifrə generatoru.
        Hər seçilmiş simvol qrupundan ən azı 1 simvol olmasını təmin edir.
        """
        if length < 6:
            length = 6
        if length > 128:
            length = 128

        pools = []
        guaranteed_chars = []

        if use_lower:
            pools.append(string.ascii_lowercase)
            guaranteed_chars.append(secrets.choice(string.ascii_lowercase))
        if use_upper:
            pools.append(string.ascii_uppercase)
            guaranteed_chars.append(secrets.choice(string.ascii_uppercase))
        if use_digits:
            pools.append(string.digits)
            guaranteed_chars.append(secrets.choice(string.digits))
        if use_symbols:
            symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            pools.append(symbols)
            guaranteed_chars.append(secrets.choice(symbols))

        if not pools:
            pools = [string.ascii_letters + string.digits]
            guaranteed_chars.append(secrets.choice(string.ascii_letters))

        all_chars = "".join(pools)
        remaining_count = max(0, length - len(guaranteed_chars))
        random_chars = [secrets.choice(all_chars) for _ in range(remaining_count)]

        password_chars = guaranteed_chars + random_chars
        secrets.SystemRandom().shuffle(password_chars)
        return "".join(password_chars)
