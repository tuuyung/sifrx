import base64
import io
import json
import logging
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import pyotp


class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {
            "SIFRX_STORAGE_TYPE": "local", "SIFRX_PEPPER_KEY": "settings-test-pepper",
            "SIFRX_LOG_DIR": str(Path(self.temp.name) / "logs"), "SIFRX_LOG_CONSOLE": "false",
            "SIFRX_LOCAL_STORAGE_PATH": str(Path(self.temp.name) / "users"),
        })
        self.env.start()
        from backend import app
        from backend.auth import AuthManager
        from backend.storage import CloudStorageManager
        from backend.account_settings import AccountSettings
        from backend.logging_setup import configure_logging
        configure_logging()
        self.module = app
        self.storage = CloudStorageManager()
        self.auth = AuthManager(self.storage)
        self.settings = AccountSettings(self.auth)
        self.globals = patch.multiple(app, storage=self.storage, auth=self.auth, account_settings=self.settings)
        self.globals.start()
        self.client = app.app.test_client()
        self.username, self.password = "settings-user", "old-master-secret"
        self.auth.register(self.username, self.password, self.password)
        self.token, _ = self.auth.login(self.username, self.password)
        self.headers = {"Authorization": "Bearer " + self.token}

    def tearDown(self):
        self.globals.stop()
        for handler in logging.getLogger("sifrx").handlers[:]:
            handler.close()
            logging.getLogger("sifrx").removeHandler(handler)
        self.env.stop()
        self.temp.cleanup()

    def post(self, action, **values):
        return self.client.post("/api/settings/" + action, json=values, headers=self.headers)

    def seed_item(self):
        from backend.crypto_engine import CentralCryptoEngine
        package = CentralCryptoEngine.encrypt_to_sifrx({"password": "private-item-value"}, self.password,
                                                       {"title": "test-title", "type": "login"})
        return self.storage.save_item(self.username, package)

    def activate(self):
        setup = self.post("2fa-setup", current_password=self.password)
        self.assertEqual(setup.status_code, 200)
        secret = setup.json["secret"]
        svg = base64.b64decode(setup.json["qr_code"].split(",", 1)[1])
        self.assertIn(b"<svg", svg)
        result = self.post("2fa-enable", current_password=self.password, otp_code=pyotp.TOTP(secret).now())
        self.assertEqual(result.status_code, 200)
        self.assertEqual(len(result.json["recovery_codes"]), 8)
        return secret, result.json["recovery_codes"]

    def test_password_change_preserves_vault_and_revokes_every_session(self):
        item_id = self.seed_item()
        other_token, _ = self.auth.login(self.username.upper(), self.password)
        old = self.storage.get_item(self.username, item_id)
        result = self.post("password", current_password=self.password, new_password="new-master-secret",
                           confirm_password="new-master-secret")
        self.assertEqual(result.status_code, 200)
        self.assertIsNone(self.auth.get_session_user(self.token))
        self.assertIsNone(self.auth.get_session_user(other_token))
        from backend.auth import AuthError
        with self.assertRaises(AuthError):
            self.auth.login(self.username, self.password)
        self.auth.login(self.username, "new-master-secret")
        from backend.crypto_engine import CentralCryptoEngine, InvalidKeyOrTamperedDataError
        new = self.storage.get_item(self.username, item_id)
        self.assertEqual(old["meta"], new["meta"])
        self.assertEqual(CentralCryptoEngine.decrypt_from_sifrx(new, "new-master-secret")["payload"]["password"], "private-item-value")
        with self.assertRaises(InvalidKeyOrTamperedDataError):
            CentralCryptoEngine.decrypt_from_sifrx(new, self.password)

    def test_failed_validation_or_corrupt_item_never_changes_password(self):
        item_id = self.seed_item()
        before = self.storage.account_snapshot(self.username)
        for values in [dict(current_password="wrong", new_password="new-master", confirm_password="new-master"),
                       dict(current_password=self.password, new_password="tiny", confirm_password="tiny"),
                       dict(current_password=self.password, new_password="new-master", confirm_password="mismatch")]:
            self.assertEqual(self.post("password", **values).status_code, 400)
            self.assertEqual(self.storage.account_snapshot(self.username), before)
        path = self.storage.get_user_dir(self.username) / (item_id + ".sifrx")
        path.write_text('{}')
        corrupt = self.storage.account_snapshot(self.username)
        self.assertEqual(self.post("password", current_password=self.password,
                                   new_password="new-master", confirm_password="new-master").status_code, 409)
        self.assertEqual(self.storage.account_snapshot(self.username), corrupt)
        self.auth.login(self.username, self.password)

    def test_delete_account_requires_confirmation_and_removes_only_own_vault(self):
        self.seed_item()
        self.auth.register("another-user", "another-password", "another-password")
        self.assertEqual(self.post("delete-account", current_password=self.password, confirmation="wrong").status_code, 400)
        self.assertTrue(self.storage.user_exists(self.username))
        self.assertEqual(self.post("delete-account", current_password=self.password, confirmation="DELETE").status_code, 200)
        self.assertFalse(self.storage.get_user_dir(self.username).exists())
        self.assertTrue(self.storage.user_exists("another-user"))
        self.assertIsNone(self.auth.get_session_user(self.token))
        self.assertEqual(self.client.get("/api/items", headers=self.headers).status_code, 401)

    def test_two_factor_activation_login_replay_recovery_and_disable(self):
        secret, codes = self.activate()
        self.assertIsNone(self.auth.get_session_user(self.token))
        result = self.client.post("/api/login", json={"username": self.username, "password": self.password})
        self.assertEqual(result.status_code, 401)
        self.assertTrue(result.json["requires_2fa"])
        self.assertNotIn("token", result.json)
        # The activation code is already consumed; wait by moving the verification clock.
        with patch("backend.two_factor.time.time", return_value=time.time() + 30):
            code = pyotp.TOTP(secret).at(time.time() + 30)
            token, _ = self.auth.login(self.username, self.password, code)
            from backend.auth import AuthError
            with self.assertRaises(AuthError):
                self.auth.login(self.username, self.password, code)
        token, _ = self.auth.login(self.username, self.password, codes[0])
        with self.assertRaises(AuthError):
            self.auth.login(self.username, self.password, codes[0])
        self.headers = {"Authorization": "Bearer " + token}
        self.assertEqual(self.post("2fa-disable", current_password=self.password).status_code, 400)
        self.assertEqual(self.post("2fa-disable", current_password=self.password, otp_code=codes[1]).status_code, 200)
        self.auth.login(self.username, self.password)
        self.assertFalse(self.settings.status(self.username)["two_factor_enabled"])
        meta_text = (self.storage.get_user_dir(self.username) / "user.meta").read_text()
        self.assertNotIn(secret, meta_text)
        log_text = "\n".join(path.read_text(encoding="utf-8")
                             for path in (Path(self.temp.name) / "logs").glob("*.jsonl"))
        for value in [secret, *codes, self.password]:
            self.assertNotIn(value, log_text)

    def test_setup_is_pending_expiring_and_session_bound(self):
        result = self.post("2fa-setup", current_password=self.password)
        self.assertFalse(self.settings.status(self.username)["two_factor_enabled"])
        self.assertEqual(self.post("2fa-enable", current_password=self.password, otp_code="invalid").status_code, 400)
        original_headers = self.headers
        other_token, _ = self.auth.login(self.username, self.password)
        self.headers = {"Authorization": "Bearer " + other_token}
        self.assertEqual(self.post("2fa-enable", current_password=self.password,
                                   otp_code=pyotp.TOTP(result.json["secret"]).now()).status_code, 400)
        self.headers = original_headers
        account_id = self.storage.compute_blind_index(self.username)
        self.settings.pending[account_id]["expires"] = 0
        self.assertEqual(self.post("2fa-enable", current_password=self.password,
                                   otp_code=pyotp.TOTP(result.json["secret"]).now()).status_code, 400)
        self.assertFalse(self.settings.status(self.username)["two_factor_enabled"])

    def test_second_factor_survives_session_manager_restart(self):
        secret, codes = self.activate()
        meta_text = (self.storage.get_user_dir(self.username) / "user.meta").read_text()
        self.assertNotIn(secret, meta_text)
        self.assertNotIn(codes[0], meta_text)
        from backend.auth import AuthManager, TwoFactorRequired
        restarted = AuthManager(self.storage)
        with self.assertRaises(TwoFactorRequired):
            restarted.login(self.username, self.password)
        token, _ = restarted.login(self.username, self.password, codes[0])
        self.assertEqual(restarted.get_session_user(token), self.username)

    def test_binary_pepper_is_preserved_and_frontend_is_static(self):
        from backend.storage import CloudStorageManager
        pepper = b"p" * 31 + b"\n"
        (self.storage.local_base_dir.parent / ".server_pepper").write_bytes(pepper)
        with patch.dict(os.environ, {"SIFRX_PEPPER_KEY": ""}):
            restarted = CloudStorageManager(str(self.storage.local_base_dir))
        self.assertEqual(restarted.pepper_key, pepper)
        for path in ("/", "/settings", "/favicon.ico", "/public/css/style.css"):
            self.assertEqual(self.client.get(path).status_code, 404)
        page = (Path(__file__).resolve().parents[2] / "public/html/settings.html").read_bytes()
        for element in [b'id="passwordForm"', b'id="deleteAccountForm"', b'id="twoFactorSetup"']:
            self.assertIn(element, page)
        self.assertNotIn(b'id="genLength"', page)
        self.assertNotIn(b"{%", page)
        self.assertNotIn(b"{{", page)

    def test_local_commit_failure_restores_original_vault(self):
        self.seed_item()
        snapshot = self.storage.account_snapshot(self.username)
        real_replace = os.replace
        calls = 0
        def fail_second(source, destination):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("simulated directory rename failure")
            return real_replace(source, destination)
        with patch("backend.storage.os.replace", side_effect=fail_second):
            result = self.post("password", current_password=self.password,
                               new_password="new-master", confirm_password="new-master")
        self.assertEqual(result.status_code, 503)
        self.assertEqual(self.storage.account_snapshot(self.username), snapshot)
        self.assertFalse(list(self.storage.local_base_dir.glob(".account-*")))
        self.auth.login(self.username, self.password)

    def test_two_factor_is_required_for_password_change_and_deletion(self):
        _, codes = self.activate()
        token, _ = self.auth.login(self.username, self.password, codes[0])
        self.headers = {"Authorization": "Bearer " + token}
        self.assertEqual(self.post("password", current_password=self.password,
                                   new_password="new-master", confirm_password="new-master").status_code, 400)
        self.assertEqual(self.post("delete-account", current_password=self.password, confirmation="DELETE").status_code, 400)
        self.assertEqual(self.post("password", current_password=self.password, otp_code=codes[1],
                                   new_password="new-master", confirm_password="new-master").status_code, 200)
        self.auth.login(self.username, "new-master", codes[2])
        self.assertTrue(self.settings.status(self.username)["two_factor_enabled"])

    def test_authentication_csrf_and_throttling(self):
        self.assertEqual(self.client.get("/api/settings").status_code, 401)
        self.assertEqual(self.post("delete-account", current_password=self.password, confirmation="DELETE").status_code, 200)
        self.auth.register(self.username, self.password, self.password)
        self.token, _ = self.auth.login(self.username, self.password)
        self.headers = {"Authorization": "Bearer " + self.token, "Origin": "https://other-site.example"}
        self.assertEqual(self.post("delete-account", current_password=self.password, confirmation="DELETE").status_code, 403)
        self.headers.pop("Origin")
        for _ in range(5):
            self.assertEqual(self.post("2fa-setup", current_password="wrong").status_code, 400)
        self.assertEqual(self.post("2fa-setup", current_password="wrong").status_code, 429)
        self.assertEqual(self.client.get("/api/settings", headers=self.headers).headers["Cache-Control"], "no-store")

    def test_cloud_partial_write_rolls_back_and_outage_blocks_security_change(self):
        self.seed_item()
        local = self.storage.account_snapshot(self.username)[0]
        class Cloud:
            def __init__(self, initial):
                self.files = dict(initial)
                self.calls = 0
            def get_paginator(self, name):
                return self
            def paginate(self, **kwargs):
                return [{"Contents": [{"Key": kwargs["Prefix"] + name} for name in self.files]}]
            def get_object(self, Key, **kwargs):
                return {"Body": io.BytesIO(self.files[Key.rsplit("/", 1)[-1]])}
            def put_object(self, Key, Body, **kwargs):
                self.calls += 1
                if self.calls == 2:
                    raise OSError("test remote write failed")
                self.files[Key.rsplit("/", 1)[-1]] = Body
            def delete_object(self, Key, **kwargs):
                self.files.pop(Key.rsplit("/", 1)[-1], None)
        cloud = Cloud(local)
        self.storage.storage_mode = "s3"
        self.storage.s3_client = cloud
        self.storage.s3_bucket = "test-bucket"
        result = self.post("password", current_password=self.password, new_password="new-master", confirm_password="new-master")
        self.assertEqual(result.status_code, 503)
        self.assertEqual(cloud.files, local)
        self.assertEqual(self.storage.account_snapshot(self.username)[0], local)
        self.auth.login(self.username, self.password)
        self.storage.storage_mode = "local"
        with patch.dict(os.environ, {"AWS_S3_BUCKET": "test-bucket", "SIFRX_STORAGE_TYPE": "auto"}):
            self.assertEqual(self.post("delete-account", current_password=self.password, confirmation="DELETE").status_code, 503)
        self.assertTrue(self.storage.user_exists(self.username))


if __name__ == "__main__":
    unittest.main()
