"""Account-security regressions using simulated S3; no real account access."""
import io
import json
import logging
import os
import unittest
from unittest.mock import patch

from botocore.exceptions import ClientError
from cryptography.exceptions import InvalidTag
import pyotp

from backend.auth import (
    AccountSettings, AuthError, AuthManager, RateLimitError, TwoFactorRequired,
    matching_counter, open_secret, seal_secret,
)
from backend.crypto_engine import CentralCryptoEngine, InvalidKeyOrTamperedDataError
from backend.logging_setup import record_category
from backend.storage import CloudStorageManager, StorageError


class FakeS3:
    def __init__(self):
        self.objects = {}
        self.fail_write = None

    def head_bucket(self, **kwargs):
        pass

    def get_paginator(self, name):
        return self

    def paginate(self, Bucket, Prefix):
        keys = sorted(key for key in self.objects if key.startswith(Prefix))
        return [{"Contents": [{"Key": key} for key in keys]}]

    def get_object(self, Bucket, Key):
        if Key not in self.objects:
            raise ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
        return {"Body": io.BytesIO(self.objects[Key])}

    def put_object(self, Bucket, Key, Body, **kwargs):
        self.objects[Key] = Body
        if Key == self.fail_write:
            self.fail_write = None
            raise RuntimeError("Simulated failure after writing")

    def delete_object(self, Bucket, Key):
        self.objects.pop(Key, None)


class AuthTests(unittest.TestCase):
    def setUp(self):
        null_handler = logging.NullHandler()
        logging.getLogger("sifrx").addHandler(null_handler)
        self.addCleanup(logging.getLogger("sifrx").removeHandler, null_handler)
        env = patch.dict(os.environ, {
            "SIFRX_PEPPER_KEY": "test-pepper", "AWS_S3_BUCKET": "test-bucket",
            "AWS_S3_PREFIX": "users/", "ARGON2_TIME_COST": "1",
            "ARGON2_MEMORY_COST": "1024", "ARGON2_PARALLELISM": "1",
        })
        env.start()
        self.addCleanup(env.stop)
        self.s3 = FakeS3()
        client = patch("backend.storage.boto3.client", return_value=self.s3)
        client.start()
        self.addCleanup(client.stop)
        self.storage = CloudStorageManager()
        self.auth = AuthManager(self.storage)
        self.settings = AccountSettings(self.auth)
        self.auth.register("alice", "old-password", "old-password")
        self.token, _ = self.auth.login("alice", "old-password")

    def seed_item(self):
        package = CentralCryptoEngine.encrypt_to_sifrx({"secret": "value"}, "old-password")
        return self.storage.save_item("alice", package)

    def activate_two_factor(self):
        setup = self.settings.begin_two_factor("alice", "old-password", self.token)
        codes = self.settings.enable_two_factor(
            "alice", "old-password", pyotp.TOTP(setup["secret"]).now(), self.token)
        return setup, codes

    def test_password_rotation_reencrypts_items_and_revokes_all_sessions(self):
        item = self.seed_item()
        other_token, _ = self.auth.login("ALICE", "old-password")
        self.settings.change_password("alice", "old-password", "new-password", "new-password", "")
        self.assertIsNone(self.auth.get_session_user(self.token))
        self.assertIsNone(self.auth.get_session_user(other_token))
        with self.assertRaises(AuthError):
            self.auth.login("alice", "old-password")
        self.auth.login("alice", "new-password")
        payload = CentralCryptoEngine.decrypt_from_sifrx(self.storage.get_item("alice", item), "new-password")
        self.assertEqual(payload["payload"], {"secret": "value"})

    def test_corrupt_item_aborts_password_change_without_writes(self):
        item = self.seed_item()
        key = self.storage._get_s3_key(self.storage.compute_blind_index("alice"), item + ".sifrx")
        self.s3.objects[key] = b'{"magic":"broken"}'
        before = dict(self.s3.objects)
        with self.assertRaises(InvalidKeyOrTamperedDataError):
            self.settings.change_password("alice", "old-password", "new-password", "new-password", "")
        self.assertEqual(self.s3.objects, before)
        self.assertEqual(self.auth.get_session_user(self.token), "alice")

    def test_failed_commit_restores_data_and_keeps_pending_setup_and_session(self):
        self.seed_item()
        self.settings.begin_two_factor("alice", "old-password", self.token)
        account_id = self.storage.compute_blind_index("alice")
        before = dict(self.s3.objects)
        self.s3.fail_write = self.storage._get_s3_key(account_id, "user.meta")
        with self.assertRaises(StorageError):
            self.settings.change_password("alice", "old-password", "new-password", "new-password", "")
        self.assertEqual(self.s3.objects, before)
        self.assertEqual(self.auth.get_session_user(self.token), "alice")
        self.assertIn(account_id, self.settings.pending)

    def test_recovery_codes_are_normalized_one_use_and_hashed(self):
        _, codes = self.activate_two_factor()
        self.assertIsNone(self.auth.get_session_user(self.token))
        with self.assertRaises(TwoFactorRequired):
            self.auth.login("alice", "old-password")
        formatted = " " + codes[0][:8].lower() + "-" + codes[0][8:].lower() + " "
        self.auth.login("alice", "old-password", formatted)
        with self.assertRaises(TwoFactorRequired):
            self.auth.login("alice", "old-password", codes[0])
        self.assertNotIn(codes[1], json.dumps(self.storage.get_user_meta("alice")))
        self.settings.disable_two_factor("alice", "old-password", codes[1])
        self.auth.login("alice", "old-password")

    def test_setup_is_bound_to_session_and_expires(self):
        setup = self.settings.begin_two_factor("alice", "old-password", self.token)
        code = pyotp.TOTP(setup["secret"]).now()
        with self.assertRaises(AuthError):
            self.settings.enable_two_factor("alice", "old-password", code, "other-session")
        account_id = self.storage.compute_blind_index("alice")
        self.settings.pending[account_id]["expires"] = 0
        with self.assertRaises(AuthError):
            self.settings.enable_two_factor("alice", "old-password", code, self.token)
        self.assertFalse(self.settings.status("alice")["two_factor_enabled"])

    def test_account_deletion_keeps_other_accounts(self):
        self.auth.register("bob", "bob-password", "bob-password")
        self.seed_item()
        self.settings.delete_account("alice", "old-password", "", "DELETE")
        self.assertFalse(self.storage.user_exists("alice"))
        self.assertTrue(self.storage.user_exists("bob"))
        self.assertIsNone(self.auth.get_session_user(self.token))

    def test_totp_replay_and_account_binding(self):
        secret = pyotp.random_base32()
        with patch("backend.auth.time.time", return_value=3000):
            code = pyotp.TOTP(secret).at(3000)
            self.assertEqual(matching_counter(secret, code), 100)
            self.assertIsNone(matching_counter(secret, code, last_counter=100))
        sealed = seal_secret(secret, self.storage.pepper_key, "alice")
        self.assertEqual(open_secret(sealed, self.storage.pepper_key, "alice"), secret)
        with self.assertRaises(InvalidTag):
            open_secret(sealed, self.storage.pepper_key, "bob")

    def test_rate_limit_is_preserved(self):
        for _ in range(5):
            with self.assertRaises(AuthError):
                self.auth.login("alice", "wrong-password")
        with self.assertRaises(RateLimitError):
            self.auth.login("alice", "old-password")

    def test_settings_logging_retains_category_without_secrets(self):
        with self.assertLogs("sifrx", level="INFO") as logs:
            self.settings.change_password("alice", "old-password", "new-password", "new-password", "")
        event = next(record for record in logs.records if record.getMessage() == "AccountSettings.change_password.completed")
        self.assertEqual(record_category(event), "settings")
        self.assertEqual(event.name, "sifrx.account_settings")
        for secret in ("alice", "old-password", "new-password", self.token):
            self.assertNotIn(secret, "\n".join(logs.output))

    def test_api_settings_and_logout_keep_token_rules(self):
        from backend import app
        with patch.multiple(app, storage=self.storage, auth=self.auth, account_settings=self.settings):
            client = app.app.test_client()
            client.set_cookie("sifrx_token", self.token)
            headers = {"Authorization": "Bearer " + self.token}
            self.assertEqual(client.get("/api/me").status_code, 200)
            self.assertEqual(client.get("/api/me", headers={"Authorization": "Bearer invalid"}).status_code, 401)
            body = {"current_password": "old-password"}
            self.assertEqual(client.post("/api/settings/2fa-setup", json=body).status_code, 403)
            self.assertEqual(client.post("/api/settings/2fa-setup", json=body, headers=headers).status_code, 200)
            self.assertEqual(client.get("/api/settings", headers=headers).status_code, 200)
            self.assertEqual(client.post("/api/logout", headers=headers).status_code, 200)
            self.assertEqual(client.get("/api/me", headers=headers).status_code, 401)


if __name__ == "__main__":
    unittest.main()
