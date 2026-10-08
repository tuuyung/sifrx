"""Encrypted local/S3 vault storage with HMAC-derived account paths.

Local copies support recovery reads. Configured cloud writes must succeed;
ordinary failures roll back staged account changes and are reported to callers.
"""

from backend.logging_setup import logged_operation
import logging
logger = logging.getLogger("sifrx.storage")


import os
import json
import uuid
import re
import hmac
import hashlib
import secrets
import shutil
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from dotenv import load_dotenv

# .env faylını mühitə yükləyirik
load_dotenv()

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False


class StorageError(Exception):
    """Bulud saxlanc xətası."""
    pass


class AccountCleanupError(StorageError):
    """Account state committed, but an encrypted temporary backup remains."""
    committed = True


class CloudStorageManager:
    """
    İstifadəçi üzrə fərdi qovluqlarda .sifrx fayllarının idarə edilməsi.
    S3 aktiv olduqda S3-dən, əks halda və ya xəta zamanı lokal qovluqdan istifadə edir.
    """
    @logged_operation
    def __init__(self, base_storage_dir: Optional[str] = None):
        # Lokal saxlanc yolu
        env_dir = os.environ.get("SIFRX_LOCAL_STORAGE_PATH") or os.environ.get("SIFRX_STORAGE_PATH")
        if base_storage_dir:
            self.local_base_dir = Path(base_storage_dir)
        elif env_dir:
            self.local_base_dir = Path(env_dir)
        else:
            self.local_base_dir = Path(__file__).resolve().parent.parent / "cloud_storage" / "users"
        
        self.local_base_dir.mkdir(parents=True, exist_ok=True)

        # Server Pepper açarını təyin edirik
        self.pepper_key = self._load_or_create_pepper()

        # Saxlanc rejimini başladırıq (S3 və ya Lokal)
        self.storage_mode = "local" # "s3" və ya "local"
        self.s3_client = None
        self.s3_bucket = None
        self.s3_prefix = os.environ.get("AWS_S3_PREFIX", "users/").lstrip("/")
        
        self._init_storage_backend()

    def _load_or_create_pepper(self) -> bytes:
        """Serverin gizli pepper açarını .env-dən və ya gizli fayldan oxuyur/yaradır."""
        env_pepper = os.environ.get("SIFRX_PEPPER_KEY", "").strip()
        if env_pepper:
            return env_pepper.encode("utf-8")

        pepper_file = self.local_base_dir.parent / ".server_pepper"
        if pepper_file.is_file():
            try:
                with open(pepper_file, "rb") as f:
                    # Random binary keys may legitimately end in whitespace bytes.
                    key = f.read()
                    if key:
                        return key
            except Exception:
                logger.warning("CloudStorageManager._load_or_create_pepper.recovery", exc_info=True)
                pass

        # Yeni kriptoqrafik 32-baytlıq açar yaradır və saxlayır
        new_key = secrets.token_bytes(32)
        try:
            with open(pepper_file, "wb") as f:
                f.write(new_key)
        except Exception:
            logger.warning("CloudStorageManager._load_or_create_pepper.recovery", exc_info=True)
            pass
        return new_key

    @logged_operation
    def _init_storage_backend(self):
        """
        Amazon S3 əlaqəsini yoxlayır.
        S3 tapılmadıqda və ya xəta olduqda avtomatik lokal saxlanca fallback edir.
        """
        storage_type = os.environ.get("SIFRX_STORAGE_TYPE", "auto").strip().lower()
        s3_bucket = os.environ.get("AWS_S3_BUCKET", "").strip()
        access_key = os.environ.get("AWS_ACCESS_KEY_ID", "").strip()
        secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY", "").strip()
        region = os.environ.get("AWS_REGION", "us-east-1").strip()
        endpoint_url = os.environ.get("AWS_S3_ENDPOINT_URL", "").strip() or None

        if storage_type == "local" or not s3_bucket:
            self.storage_mode = "local"
            logger.info("storage.local_selected")
            return

        if not BOTO3_AVAILABLE:
            logger.warning("storage.s3_dependency_missing")
            self.storage_mode = "local"
            return

        # S3 konfiqurasiyasını yoxlayırıq
        try:
            client_kwargs = {
                "service_name": "s3",
                "region_name": region
            }
            if access_key and secret_key:
                client_kwargs["aws_access_key_id"] = access_key
                client_kwargs["aws_secret_access_key"] = secret_key
                session_token = os.environ.get("AWS_SESSION_TOKEN", "").strip()
                if session_token:
                    client_kwargs["aws_session_token"] = session_token
            if endpoint_url:
                client_kwargs["endpoint_url"] = endpoint_url

            client = boto3.client(**client_kwargs)
            # S3 bucket-in mövcudluğunu və əlaqəni test edirik
            client.head_bucket(Bucket=s3_bucket)
            
            self.s3_client = client
            self.s3_bucket = s3_bucket
            self.storage_mode = "s3"
            logger.info("storage.s3_connected")
        except Exception as e:
            # S3 ünvanı tapılmadıqda və ya qoşulma xətasında LOKAL FALLBACK
            logger.warning("CloudStorageManager._init_storage_backend.recovery", exc_info=True)
            logger.warning("storage.s3_connection_failed")
            logger.warning("storage.local_fallback")
            self.storage_mode = "local"
            self.s3_client = None

    @logged_operation
    def compute_blind_index(self, username: str) -> str:
        """İstifadəçi adını HMAC-SHA256 ilə anonim heş identifikatora çevirir."""
        if not username:
            raise StorageError("İstifadəçi adı boş ola bilməz.")
        normalized = username.strip().lower().encode("utf-8")
        return hmac.new(self.pepper_key, normalized, hashlib.sha256).hexdigest()

    def _get_s3_key(self, blind_id: str, filename: str) -> str:
        return f"{self.s3_prefix}{blind_id}/{filename}"

    @logged_operation
    def get_user_dir(self, username: str) -> Path:
        """Lokal qovluq yolunu qaytarır və köhnə qovluqları avtomatik miqrasiya edir."""
        blind_id = self.compute_blind_index(username)
        blind_dir = self.local_base_dir / blind_id

        if blind_dir.is_dir():
            return blind_dir

        # Köhnə açıq adlı qovluq varsa, avtomatik miqrasiya
        clean_name = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', username.strip().lower())
        legacy_dir = self.local_base_dir / clean_name
        if legacy_dir.is_dir():
            try:
                legacy_dir.rename(blind_dir)
                meta_file = blind_dir / "user.meta"
                if meta_file.is_file():
                    with open(meta_file, "r", encoding="utf-8") as f:
                        meta_data = json.load(f)
                    meta_data.pop("username", None)
                    meta_data["blind_index"] = blind_id
                    with open(meta_file, "w", encoding="utf-8") as f:
                        json.dump(meta_data, f, indent=2, ensure_ascii=False)
                return blind_dir
            except Exception:
                logger.warning("CloudStorageManager.get_user_dir.recovery", exc_info=True)
                return legacy_dir

        return blind_dir

    @logged_operation
    def ensure_user_vault(self, username: str) -> Path:
        """İstifadəçi qovluğunu təmin edir."""
        user_dir = self.get_user_dir(username)
        user_dir.mkdir(parents=True, exist_ok=True)
        return user_dir

    @logged_operation
    def user_exists(self, username: str) -> bool:
        """İstifadəçinin qeydiyyatdan keçdiyini yoxlayır."""
        snapshot = self.account_snapshot(username)
        return "user.meta" in snapshot[0] or "user.meta" in snapshot[1]

    @logged_operation
    def save_user_meta(self, username: str, meta: Dict[str, Any]) -> None:
        clean_meta = dict(meta)
        clean_meta.pop("username", None)
        clean_meta["blind_index"] = self.compute_blind_index(username)
        snapshot = self.account_snapshot(username)
        files = {**snapshot[1], **snapshot[0]}
        files["user.meta"] = json.dumps(clean_meta, ensure_ascii=False).encode("utf-8")
        self.replace_account(username, files, snapshot)

    @logged_operation
    def get_user_meta(self, username: str) -> Optional[Dict[str, Any]]:
        """İstifadəçinin metadata məlumatlarını oxuyur."""
        blind_id = self.compute_blind_index(username)

        # 1. S3-dən oxumağa cəhd
        if self.storage_mode == "s3" and self.s3_client:
            try:
                key = self._get_s3_key(blind_id, "user.meta")
                resp = self.s3_client.get_object(Bucket=self.s3_bucket, Key=key)
                content = resp["Body"].read().decode("utf-8")
                return json.loads(content)
            except Exception:
                # S3-də xəta olarsa, dərhal lokal fayla fallback
                logger.warning("CloudStorageManager.get_user_meta.recovery", exc_info=True)
                pass

        # 2. Lokal saxlancdan oxuma
        user_dir = self.get_user_dir(username)
        meta_file = user_dir / "user.meta"
        if not meta_file.is_file():
            return None
        with open(meta_file, "r", encoding="utf-8") as f:
            return json.load(f)

    @logged_operation
    def save_item(self, username: str, sifrx_package: Dict[str, Any], item_id: Optional[str] = None) -> str:
        """Şifrələnmiş .sifrx faylını S3 və ya lokal saxlancda qeyd edir."""
        if not item_id:
            item_id = sifrx_package.get("meta", {}).get("id") or str(uuid.uuid4())

        if "meta" not in sifrx_package:
            sifrx_package["meta"] = {}
        sifrx_package["meta"]["id"] = item_id
        if "created_at" not in sifrx_package["meta"]:
            sifrx_package["meta"]["created_at"] = datetime.now(timezone.utc).isoformat()
        sifrx_package["meta"]["updated_at"] = datetime.now(timezone.utc).isoformat()

        payload_bytes = json.dumps(sifrx_package, indent=2, ensure_ascii=False).encode("utf-8")

        if not re.fullmatch(r"[a-zA-Z0-9_-]+", item_id):
            raise StorageError("Invalid item ID.")
        snapshot = self.account_snapshot(username)
        files = {**snapshot[1], **snapshot[0]}
        files[f"{item_id}.sifrx"] = payload_bytes
        self.replace_account(username, files, snapshot)

        return item_id

    @logged_operation
    def get_item(self, username: str, item_id: str) -> Optional[Dict[str, Any]]:
        """İstifadəçinin .sifrx faylını S3 və ya lokal saxlancdan oxuyur."""
        blind_id = self.compute_blind_index(username)
        safe_id = re.sub(r'[^a-zA-Z0-9_\-]', '', item_id)

        # 1. S3 cəhdi
        if self.storage_mode == "s3" and self.s3_client:
            try:
                key = self._get_s3_key(blind_id, f"{safe_id}.sifrx")
                resp = self.s3_client.get_object(Bucket=self.s3_bucket, Key=key)
                content = resp["Body"].read().decode("utf-8")
                return json.loads(content)
            except Exception:
                logger.warning("CloudStorageManager.get_item.recovery", exc_info=True)
                pass

        # 2. Lokal Fallback
        user_dir = self.get_user_dir(username)
        file_path = user_dir / f"{safe_id}.sifrx"
        if not file_path.is_file():
            return None
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)

    @logged_operation
    def list_items(self, username: str) -> List[Dict[str, Any]]:
        """İstifadəçinin bütün .sifrx fayllarının siyahısını qaytarır."""
        blind_id = self.compute_blind_index(username)
        items_dict = {}

        # 1. S3 cəhdi
        if self.storage_mode == "s3" and self.s3_client:
            try:
                prefix = f"{self.s3_prefix}{blind_id}/"
                paginator = self.s3_client.get_paginator("list_objects_v2")
                for page in paginator.paginate(Bucket=self.s3_bucket, Prefix=prefix):
                    for obj in page.get("Contents", []):
                        key = obj["Key"]
                        if key.endswith(".sifrx"):
                            item_id = Path(key).stem
                            # Obyekti oxuyub metadata çıxarırıq
                            try:
                                resp = self.s3_client.get_object(Bucket=self.s3_bucket, Key=key)
                                data = json.loads(resp["Body"].read().decode("utf-8"))
                                meta = data.get("meta", {})
                                items_dict[item_id] = {
                                    "id": meta.get("id", item_id),
                                    "type": meta.get("type", "login"),
                                    "title": meta.get("title", "Adsız"),
                                    "created_at": meta.get("created_at"),
                                    "updated_at": meta.get("updated_at")
                                }
                            except Exception:
                                logger.warning("CloudStorageManager.list_items.recovery", exc_info=True)
                                continue
                if items_dict:
                    sorted_items = list(items_dict.values())
                    sorted_items.sort(key=lambda x: x.get("updated_at") or "", reverse=True)
                    return sorted_items
            except Exception as e:
                logger.warning("CloudStorageManager.list_items.recovery", exc_info=True)
                logger.warning("storage.list_local_fallback")

        # 2. Lokal saxlanc (Fallback)
        user_dir = self.get_user_dir(username)
        if not user_dir.is_dir():
            return []

        for file_path in user_dir.glob("*.sifrx"):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    meta = data.get("meta", {})
                    item_id = meta.get("id", file_path.stem)
                    items_dict[item_id] = {
                        "id": item_id,
                        "type": meta.get("type", "login"),
                        "title": meta.get("title", "Adsız"),
                        "created_at": meta.get("created_at"),
                        "updated_at": meta.get("updated_at")
                    }
            except Exception:
                logger.warning("CloudStorageManager.list_items.recovery", exc_info=True)
                continue

        sorted_items = list(items_dict.values())
        sorted_items.sort(key=lambda x: x.get("updated_at") or "", reverse=True)
        return sorted_items

    @logged_operation
    def delete_item(self, username: str, item_id: str) -> bool:
        """İstifadəçinin .sifrx faylını S3 və lokal saxlancdan silir."""
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", item_id):
            raise StorageError("Invalid item ID.")
        snapshot = self.account_snapshot(username)
        files = {**snapshot[1], **snapshot[0]}
        name = f"{item_id}.sifrx"
        if name not in files:
            return False
        del files[name]
        self.replace_account(username, files, snapshot)
        return True

    def _account_dir(self, username):
        root = self.local_base_dir.resolve()
        target = self.get_user_dir(username).resolve()
        if target.parent != root or target == root:
            raise StorageError("Hesab saxlanc yolu təhlükəsiz deyil.")
        return target

    @logged_operation
    def account_snapshot(self, username):
        """Read every account file strictly; security changes never skip bad files."""
        local = {}
        directory = self._account_dir(username)
        if directory.exists():
            for file in directory.iterdir():
                if file.is_symlink() or not file.is_file():
                    raise StorageError("Hesab saxlancında gözlənilməz fayl var.")
                local[file.name] = file.read_bytes()
        remote = {}
        # A configured but unavailable cloud must not retain an old password/2FA state.
        if os.environ.get("AWS_S3_BUCKET", "").strip() and os.environ.get("SIFRX_STORAGE_TYPE", "auto") != "local":
            if self.storage_mode != "s3" or not self.s3_client:
                raise StorageError("Bulud saxlancı hazır deyil. Yenidən cəhd edin.")
        if self.storage_mode == "s3":
            prefix = self._get_s3_key(self.compute_blind_index(username), "")
            for page in self.s3_client.get_paginator("list_objects_v2").paginate(Bucket=self.s3_bucket, Prefix=prefix):
                for obj in page.get("Contents", []):
                    name = obj["Key"][len(prefix):]
                    if not name or "/" in name or "\\" in name or name in (".", ".."):
                        raise StorageError("Bulud hesabında gözlənilməz fayl var.")
                    remote[name] = self.s3_client.get_object(Bucket=self.s3_bucket, Key=obj["Key"])["Body"].read()
        return local, remote

    @logged_operation
    def replace_account(self, username, files, snapshot=None):
        """Stage local changes and roll back both stores on ordinary write failures.

        files=None deletes the account. Remote metadata is always written last.
        Caller serializes account operations in this single-process application.
        """
        local, remote = snapshot if snapshot is not None else self.account_snapshot(username)
        target = self._account_dir(username)
        stage = Path(tempfile.mkdtemp(prefix=".account-stage-", dir=self.local_base_dir)).resolve()
        backup = self.local_base_dir.resolve() / (".account-backup-" + uuid.uuid4().hex)
        moved = False
        touched = []
        prefix = self._get_s3_key(self.compute_blind_index(username), "")
        try:
            for name, content in (files or {}).items():
                if Path(name).name != name or name in (".", "..") or "/" in name or "\\" in name:
                    raise StorageError("Yanlış hesab faylı adı.")
                (stage / name).write_bytes(content)
            if self.storage_mode == "s3":
                names = sorted(set(remote) | set(files or {}), key=lambda name: name == "user.meta")
                for name in names:
                    if files is not None and name in remote and files.get(name) == remote[name]:
                        continue
                    touched.append(name)
                    if files is not None and name in files:
                        self.s3_client.put_object(Bucket=self.s3_bucket, Key=prefix + name,
                                                  Body=files[name], ContentType="application/json")
                    else:
                        self.s3_client.delete_object(Bucket=self.s3_bucket, Key=prefix + name)
            if target.exists():
                os.replace(target, backup)
                moved = True
            if files is not None:
                os.replace(stage, target)
        except Exception:
            if moved:
                os.replace(backup, target)
            if self.storage_mode == "s3":
                try:
                    for name in touched:
                        if name in remote:
                            self.s3_client.put_object(Bucket=self.s3_bucket, Key=prefix + name,
                                                      Body=remote[name], ContentType="application/json")
                        else:
                            self.s3_client.delete_object(Bucket=self.s3_bucket, Key=prefix + name)
                except Exception:
                    logger.critical("storage.account_rollback_failed", exc_info=True)
                    raise StorageError("Bulud yeniləməsi bərpa olunmadı. Administratorla əlaqə saxlayın.") from None
            raise StorageError("Storage operation failed; changes were rolled back.") from None
        finally:
            if stage.exists():
                shutil.rmtree(stage)
        if backup.exists():
            try:
                shutil.rmtree(backup)
            except OSError:
                logger.error("storage.account_backup_cleanup_failed", exc_info=True)
                raise AccountCleanupError("Köhnə hesab nüsxəsi silinmədi. Administratorla əlaqə saxlayın.") from None
