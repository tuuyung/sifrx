"""Regression checks run against temporary local accounts and simulated S3."""
import io
import logging
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {
            "SIFRX_STORAGE_TYPE": "local", "SIFRX_PEPPER_KEY": "security-test-pepper",
            "SIFRX_LOG_DIR": str(Path(self.temp.name) / "logs"),
            "SIFRX_LOG_CONSOLE": "false",
            "SIFRX_LOCAL_STORAGE_PATH": str(Path(self.temp.name) / "users"),
            "ARGON2_TIME_COST": "1", "ARGON2_MEMORY_COST": "1024", "ARGON2_PARALLELISM": "1",
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
        self.globals = patch.multiple(app, storage=self.storage, auth=self.auth,
                                     account_settings=AccountSettings(self.auth))
        self.globals.start()
        self.client = app.app.test_client()
        self.password = "security-test-password"
        self.auth.register("review-user", self.password, self.password)
        token, _ = self.auth.login("review-user", self.password)
        self.headers = {"Authorization": "Bearer " + token}

    def tearDown(self):
        self.globals.stop()
        for handler in logging.getLogger("sifrx").handlers[:]:
            handler.close()
            logging.getLogger("sifrx").removeHandler(handler)
        self.env.stop()
        self.temp.cleanup()

    def test_saved_argon2_parameters_survive_configuration_changes(self):
        from backend.crypto_engine import CentralCryptoEngine, InvalidKeyOrTamperedDataError
        package = CentralCryptoEngine.encrypt_to_sifrx({"secret": "example"}, self.password)
        with patch.dict(os.environ, {"ARGON2_TIME_COST": "2", "ARGON2_MEMORY_COST": "2048"}):
            self.assertEqual(CentralCryptoEngine.decrypt_from_sifrx(package, self.password)["payload"],
                             {"secret": "example"})
        package["argon2_params"]["memory_cost"] = 2 ** 30
        with self.assertRaises(InvalidKeyOrTamperedDataError):
            CentralCryptoEngine.decrypt_from_sifrx(package, self.password)

    def test_invalid_api_shapes_and_types_are_rejected(self):
        cases = [
            ("/api/register", ["invalid"]), ("/api/register", {"username": 12}),
            ("/api/login", {"password": []}), ("/api/login", {"password": "x" * 1025}),
            ("/api/generate-password", {"length": "invalid"}),
            ("/api/generate-password", {"length": True}),
            ("/api/generate-password", {"length": 129}),
            ("/api/generate-password", {"uppercase": "false"}),
            ("/api/items", {"master_password": self.password, "data": []}),
            ("/api/items", {"master_password": self.password, "data": {"title": 12}}),
            ("/api/items", {"master_password": self.password, "type": "unknown", "data": {}}),
            ("/api/items/example/decrypt", {"master_password": []}),
        ]
        for path, body in cases:
            with self.subTest(path=path, body=body):
                response = self.client.post(path, json=body, headers=self.headers)
                self.assertEqual(response.status_code, 400)
                self.assertIsInstance(response.json["error"], str)
        self.assertEqual(self.client.post("/api/register", data="{bad",
                         content_type="application/json").status_code, 400)
        self.assertEqual(self.client.post("/api/register", data="x" * (1024 * 1024 + 1),
                         content_type="application/json").status_code, 413)

    def connect_cloud(self):
        prefix = self.storage._get_s3_key(self.storage.compute_blind_index("review-user"), "")
        class Cloud:
            def __init__(self, files):
                self.files = dict(files)
                self.fail_upload = False
                self.fail_delete = False
            def get_paginator(self, name):
                return self
            def paginate(self, **kwargs):
                if kwargs["Prefix"] != prefix:
                    return [{"Contents": []}]
                return [{"Contents": [{"Key": kwargs["Prefix"] + name} for name in self.files]}]
            def get_object(self, Key, **kwargs):
                return {"Body": io.BytesIO(self.files[Key.rsplit("/", 1)[-1]])}
            def put_object(self, Key, Body, **kwargs):
                if self.fail_upload:
                    raise OSError("private-upload-error")
                self.files[Key.rsplit("/", 1)[-1]] = Body
            def delete_object(self, Key, **kwargs):
                if self.fail_delete:
                    raise OSError("private-delete-error")
                if Key.startswith(prefix):
                    self.files.pop(Key.rsplit("/", 1)[-1], None)
        cloud = Cloud(self.storage.account_snapshot("review-user")[0])
        self.storage.storage_mode = "s3"
        self.storage.s3_client = cloud
        self.storage.s3_bucket = "simulated-bucket"
        return cloud

    def test_failed_cloud_upload_returns_error_without_local_commit(self):
        cloud = self.connect_cloud()
        before = dict(cloud.files)
        cloud.fail_upload = True
        response = self.client.post("/api/items", headers=self.headers,
                    json={"master_password": self.password, "data": {"title": "test"}})
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("private-upload-error", response.get_data(as_text=True))
        self.assertEqual(cloud.files, before)
        self.assertEqual(self.storage.account_snapshot("review-user")[0], before)

    def test_failed_cloud_delete_preserves_local_item_and_returns_error(self):
        from backend.crypto_engine import CentralCryptoEngine
        item = self.storage.save_item("review-user",
                CentralCryptoEngine.encrypt_to_sifrx({"title": "test"}, self.password))
        cloud = self.connect_cloud()
        before = dict(cloud.files)
        cloud.fail_delete = True
        response = self.client.delete("/api/items/" + item, headers=self.headers)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(cloud.files, before)
        self.assertEqual(self.storage.account_snapshot("review-user")[0], before)

    def test_failed_registration_does_not_create_a_local_only_account(self):
        cloud = self.connect_cloud()
        cloud.fail_upload = True
        response = self.client.post("/api/register", json={
            "username": "new-review-user", "password": self.password, "confirm_password": self.password})
        self.assertEqual(response.status_code, 503)
        self.assertFalse(self.storage.user_exists("new-review-user"))


if __name__ == "__main__":
    unittest.main()
