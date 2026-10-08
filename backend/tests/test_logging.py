"""Integration checks use temporary vaults and logs, never real user files."""
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


class LoggingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.env = patch.dict(os.environ, {
            "SIFRX_LOG_DIR": str(Path(cls.temp.name) / "logs"),
            "SIFRX_LOCAL_STORAGE_PATH": str(Path(cls.temp.name) / "vaults"),
            "SIFRX_STORAGE_TYPE": "local", "SIFRX_LOG_CONSOLE": "false",
            "SIFRX_LOG_LEVEL": "DEBUG", "SIFRX_PEPPER_KEY": "test-pepper-secret",
        })
        cls.env.start()
        from backend import app
        cls.module = app
        cls.client = app.app.test_client()

    @classmethod
    def tearDownClass(cls):
        logger = logging.getLogger("sifrx")
        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)
        cls.env.stop()
        cls.temp.cleanup()

    def records(self):
        directory = Path(self.temp.name) / "logs"
        return [json.loads(line) for path in directory.glob("*.jsonl")
                for line in path.read_text(encoding="utf-8").splitlines()]

    def test_category_routing_and_error_copy(self):
        from backend.logging_setup import LOG_FILES, configure_logging
        expected = {"sifrx.http": "requests", "sifrx.auth": "authentication",
                    "sifrx.storage": "storage", "sifrx.crypto_engine": "crypto",
                    "sifrx.account_settings": "settings", "sifrx.client": "frontend",
                    "sifrx.runtime": "application", "sifrx.future_component": "application"}
        for name in expected:
            logging.getLogger(name).info("category.check." + name)
        logging.getLogger("sifrx.storage").error("category.error_check")
        logger = logging.getLogger("sifrx")
        handlers = list(logger.handlers)
        self.assertIs(configure_logging(), logger)
        self.assertEqual(logger.handlers, handlers)
        directory = Path(self.temp.name) / "logs"
        self.assertEqual({path.stem for path in directory.glob("*.jsonl")}, set(LOG_FILES))
        contents = {path.stem: [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
                    for path in directory.glob("*.jsonl")}
        for name, category in expected.items():
            matches = [(file, record) for file, records in contents.items() for record in records
                       if record["event"] == "category.check." + name]
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0][0], category)
            self.assertEqual(matches[0][1]["category"], category)
        files = {file for file, records in contents.items()
                 if any(record["event"] == "category.error_check" for record in records)}
        self.assertEqual(files, {"storage", "errors"})
        for record in contents["errors"]:
            self.assertIn(record["level"], ("ERROR", "CRITICAL"))

    def test_vault_workflow_and_secret_exclusion(self):
        username, password = "private-test-user", "private-master-secret"
        response = self.client.post("/api/register", json={
            "username": username, "password": password, "confirm_password": password})
        self.assertEqual(response.status_code, 201)
        response = self.client.post("/api/login", json={"username": username, "password": password})
        self.assertEqual(response.status_code, 200)
        token = response.json["token"]
        response = self.client.post("/api/items", json={
            "master_password": password, "type": "login",
            "data": {"title": "private-vault-title", "password": "private-vault-secret"}})
        self.assertEqual(response.status_code, 201)
        item_id = response.json["id"]
        self.assertEqual(self.client.get("/api/items").status_code, 200)
        response = self.client.post(f"/api/items/{item_id}/decrypt", json={"master_password": password})
        self.assertEqual(response.status_code, 200)
        response = self.client.post(f"/api/items/{item_id}/decrypt", json={"master_password": "wrong-secret"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.client.delete(f"/api/items/{item_id}").status_code, 200)
        self.assertEqual(self.client.post("/api/logout").status_code, 200)
        self.assertEqual(self.client.get("/api/items").status_code, 401)
        self.client.get("/missing-private-path?token=private-query-secret")
        with patch.object(self.module.auth, "login", side_effect=RuntimeError("private-exception-secret")):
            self.assertEqual(self.client.post("/api/login", json={}).status_code, 500)
        records = self.records()
        text = json.dumps(records)
        for secret in [username, password, token, item_id, "private-vault-title", "private-vault-secret",
                       "wrong-secret", "private-query-secret", "missing-private-path", "private-exception-secret"]:
            self.assertNotIn(secret, text)
        correlated = [r for r in records if r.get("request_id") == response.headers["X-Request-ID"]]
        self.assertTrue(any(r["event"] == "request.completed" and r["status"] == 403 for r in correlated))
        self.assertTrue(any(r.get("exception_type") == "RuntimeError" and r.get("frames") for r in records))
        for event in ["AuthManager.register.completed", "CloudStorageManager.save_item.completed",
                      "CentralCryptoEngine.decrypt_from_sifrx.completed"]:
            self.assertTrue(any(r["event"] == event for r in records), event)

    def test_browser_validation_and_rate_limit(self):
        self.module._client_log_times.clear()
        self.assertEqual(self.client.post("/api/client-events", json={"event": []}).status_code, 400)
        self.assertEqual(self.client.post("/api/client-events", json={"event": "private-browser-secret"}).status_code, 400)
        self.assertEqual(self.client.post("/api/client-events", data="x" * 513).status_code, 413)
        self.assertEqual(self.client.post("/api/client-events", json={"event": "browser.error"},
                                         headers={"Sec-Fetch-Site": "cross-site"}).status_code, 403)
        for _ in range(60):
            self.assertEqual(self.client.post("/api/client-events", json={"event": "browser.error"}).status_code, 204)
        self.assertEqual(self.client.post("/api/client-events", json={"event": "browser.error"}).status_code, 429)
        self.assertNotIn("private-browser-secret", json.dumps(self.records()))

    def test_unhandled_exception_and_rotation(self):
        from backend.logging_setup import JsonFormatter
        with patch.object(self.module.CentralCryptoEngine, "generate_password",
                          side_effect=RuntimeError("unhandled-private-secret")):
            self.assertEqual(self.client.post("/api/generate-password", json={}).status_code, 500)
        self.assertTrue(any(r["event"] == "request.unhandled_exception" for r in self.records()))
        self.assertNotIn("unhandled-private-secret", json.dumps(self.records()))
        path = Path(self.temp.name) / "rotation.jsonl"
        handler = RotatingFileHandler(path, maxBytes=256, backupCount=2, encoding="utf-8")
        handler.setFormatter(JsonFormatter())
        try:
            for _ in range(20):
                handler.handle(logging.LogRecord("sifrx.test", logging.INFO, __file__, 1, "rotation.check", (), None))
        finally:
            handler.close()
        self.assertTrue(Path(str(path) + ".1").is_file())
        self.assertTrue(Path(str(path) + ".2").is_file())
        self.assertFalse(Path(str(path) + ".3").exists())
        for file in path.parent.glob("rotation.jsonl*"):
            for line in file.read_text(encoding="utf-8").splitlines():
                self.assertEqual(json.loads(line)["event"], "rotation.check")


if __name__ == "__main__":
    unittest.main()
