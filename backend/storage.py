"""S3-only encrypted vault storage; account snapshots stay in memory."""
import os
import json
import uuid
import re
import hmac
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional
import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv
from backend.logging_setup import logged_operation

load_dotenv()
logger = logging.getLogger("sifrx.storage")


class StorageError(Exception):
    """Cloud storage operation failed."""


class CloudStorageManager:
    @logged_operation
    def __init__(self):
        pepper = os.environ.get("SIFRX_PEPPER_KEY", "")
        if not pepper.strip():
            raise StorageError("SIFRX_PEPPER_KEY is required.")
        self.pepper_key = pepper.encode("utf-8")
        self.s3_bucket = os.environ.get("AWS_S3_BUCKET", "").strip()
        if not self.s3_bucket:
            raise StorageError("AWS_S3_BUCKET is required.")
        self.s3_prefix = os.environ.get("AWS_S3_PREFIX", "users/").strip("/")
        if self.s3_prefix:
            self.s3_prefix += "/"
        self._init_storage_backend()

    @logged_operation
    def _init_storage_backend(self):
        kwargs = {"service_name": "s3", "region_name": os.environ.get("AWS_REGION", "us-east-1")}
        endpoint = os.environ.get("AWS_S3_ENDPOINT_URL", "").strip()
        if endpoint:
            kwargs["endpoint_url"] = endpoint
        try:
            self.s3_client = boto3.client(**kwargs)
            self.s3_client.head_bucket(Bucket=self.s3_bucket)
        except Exception as error:
            raise StorageError("Unable to connect to S3.") from error
        logger.info("storage.s3_connected")

    @logged_operation
    def compute_blind_index(self, username: str) -> str:
        """İstifadəçi adını HMAC-SHA256 ilə anonim heş identifikatora çevirir."""
        if not username or not username.strip():
            raise StorageError("İstifadəçi adı boş ola bilməz.")
        normalized = username.strip().lower().encode("utf-8")
        return hmac.new(self.pepper_key, normalized, hashlib.sha256).hexdigest()

    def _get_s3_key(self, blind_id: str, filename: str) -> str:
        return f"{self.s3_prefix}{blind_id}/{filename}"

    @staticmethod
    def _validate_filename(name):
        if not isinstance(name, str) or not name or name in (".", "..") or "/" in name or "\\" in name:
            raise StorageError("Invalid account filename.")

    def _read_json(self, username, filename):
        key = self._get_s3_key(self.compute_blind_index(username), filename)
        try:
            response = self.s3_client.get_object(Bucket=self.s3_bucket, Key=key)
            return json.loads(response["Body"].read())
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") == "NoSuchKey":
                return None
            raise StorageError("Unable to read from S3.") from error
        except Exception as error:
            raise StorageError("Unable to read account data.") from error

    @logged_operation
    def user_exists(self, username):
        return self.get_user_meta(username) is not None

    @logged_operation
    def get_user_meta(self, username):
        return self._read_json(username, "user.meta")

    @logged_operation
    def save_user_meta(self, username, meta):
        snapshot = self.account_snapshot(username)
        self.save_account_meta(username, dict(snapshot), meta, snapshot)

    def load_account(self, username):
        """Return an original snapshot, editable files and parsed account metadata."""
        snapshot = self.account_snapshot(username)
        files = dict(snapshot)
        meta = json.loads(files["user.meta"]) if "user.meta" in files else None
        return snapshot, files, meta

    def save_account_meta(self, username, files, meta, snapshot):
        """Commit metadata together with edited vault files using one snapshot."""
        clean_meta = dict(meta)
        clean_meta.pop("username", None)
        clean_meta["blind_index"] = self.compute_blind_index(username)
        files["user.meta"] = json.dumps(clean_meta, ensure_ascii=False).encode("utf-8")
        self.replace_account(username, files, snapshot)

    @staticmethod
    def _item_filename(item_id):
        if not isinstance(item_id, str) or not re.fullmatch(r"[a-zA-Z0-9_-]+", item_id):
            raise StorageError("Invalid item ID.")
        return f"{item_id}.sifrx"

    @logged_operation
    def get_item(self, username, item_id):
        return self._read_json(username, self._item_filename(item_id))

    @logged_operation
    def list_items(self, username):
        items = []
        for name, content in self.account_snapshot(username).items():
            if name.endswith(".sifrx"):
                try:
                    meta = json.loads(content).get("meta", {})
                    items.append({"id": meta.get("id", name[:-6]), "type": meta.get("type", "login"),
                                  "title": meta.get("title", "Adsız"), "created_at": meta.get("created_at"),
                                  "updated_at": meta.get("updated_at")})
                except Exception as error:
                    raise StorageError("Unable to read vault item metadata.") from error
        return sorted(items, key=lambda item: item.get("updated_at") or "", reverse=True)

    @logged_operation
    def account_snapshot(self, username):
        """Read every remote account file into memory; never cache on disk."""
        prefix = self._get_s3_key(self.compute_blind_index(username), "")
        files = {}
        try:
            for page in self.s3_client.get_paginator("list_objects_v2").paginate(Bucket=self.s3_bucket, Prefix=prefix):
                for obj in page.get("Contents", []):
                    name = obj["Key"][len(prefix):]
                    self._validate_filename(name)
                    files[name] = self.s3_client.get_object(Bucket=self.s3_bucket, Key=obj["Key"])["Body"].read()
        except Exception as error:
            raise StorageError("Unable to read account snapshot from S3.") from error
        return files

    @logged_operation
    def replace_account(self, username, files, snapshot=None):
        """Write metadata last; restore S3 from memory on ordinary failures.

        files=None deletes the account. Caller serializes account operations.
        """
        remote = snapshot if snapshot is not None else self.account_snapshot(username)
        desired = files or {}
        for name in desired:
            self._validate_filename(name)
        prefix = self._get_s3_key(self.compute_blind_index(username), "")
        touched = []
        try:
            for name in sorted(set(remote) | set(desired), key=lambda name: (name == "user.meta", name)):
                if name in remote and name in desired and desired[name] == remote[name]:
                    continue
                touched.append(name)
                self._write_account_file(prefix, name, desired)
        except Exception:
            try:
                for name in sorted(touched, key=lambda name: (name == "user.meta", name)):
                    self._write_account_file(prefix, name, remote)
            except Exception:
                logger.critical("storage.account_rollback_failed", exc_info=True)
                raise StorageError("S3 rollback failed. Contact the administrator.") from None
            raise StorageError("Storage operation failed; changes were rolled back.") from None

    def _write_account_file(self, prefix, name, files):
        """Apply the same S3 write/delete logic during commit and rollback."""
        if name in files:
            self.s3_client.put_object(Bucket=self.s3_bucket, Key=prefix + name,
                                      Body=files[name], ContentType="application/json")
        else:
            self.s3_client.delete_object(Bucket=self.s3_bucket, Key=prefix + name)

    @logged_operation
    def save_item(self, username: str, sifrx_package: Dict[str, Any], item_id: Optional[str] = None) -> str:
        """Save an encrypted .sifrx object to S3."""
        if not item_id:
            item_id = sifrx_package.get("meta", {}).get("id") or str(uuid.uuid4())
        filename = self._item_filename(item_id)

        if "meta" not in sifrx_package:
            sifrx_package["meta"] = {}
        sifrx_package["meta"]["id"] = item_id
        if "created_at" not in sifrx_package["meta"]:
            sifrx_package["meta"]["created_at"] = datetime.now(timezone.utc).isoformat()
        sifrx_package["meta"]["updated_at"] = datetime.now(timezone.utc).isoformat()

        payload_bytes = json.dumps(sifrx_package, indent=2, ensure_ascii=False).encode("utf-8")

        snapshot = self.account_snapshot(username)
        files = dict(snapshot)
        files[filename] = payload_bytes
        self.replace_account(username, files, snapshot)

        return item_id

    @logged_operation
    def delete_item(self, username: str, item_id: str) -> bool:
        """Delete an encrypted .sifrx object from S3."""
        name = self._item_filename(item_id)
        snapshot = self.account_snapshot(username)
        files = dict(snapshot)
        if name not in files:
            return False
        del files[name]
        self.replace_account(username, files, snapshot)
        return True
