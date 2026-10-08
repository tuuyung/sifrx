"""SifrX REST API exposed as a WSGI application behind Nginx."""

import os
import sys
import logging
from pathlib import Path

# Direct script execution puts backend/, rather than the project root, on sys.path.
if __name__ == "__main__" and not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv

load_dotenv()

from backend.logging_setup import configure_logging, install_request_logging
logger = configure_logging()
request_logger = logging.getLogger("sifrx.http")
settings_logger = logging.getLogger("sifrx.account_settings")
client_logger = logging.getLogger("sifrx.client")

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

from flask import Flask, request, jsonify, g
from backend.crypto_engine import CentralCryptoEngine, CryptoError, InvalidKeyOrTamperedDataError
from backend.storage import CloudStorageManager, StorageError
from backend.auth import AccountSettings, AuthManager, AuthError, TwoFactorRequired, RateLimitError

app = Flask(__name__, static_folder=None)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", os.urandom(24))
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024

install_request_logging(app)

storage = CloudStorageManager()
auth = AuthManager(storage)
account_settings = AccountSettings(auth)

# The existing sessions are process-local. Serialize vault/security operations so
# requests cannot read or write an account halfway through a credential change.
from threading import RLock
from urllib.parse import urlsplit
_account_request_lock = RLock()


@app.before_request
def protect_account_requests():
    if request.path.startswith("/api/") and request.path != "/api/client-events":
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("Origin")
            if (request.headers.get("Sec-Fetch-Site") == "cross-site"
                    or (origin and urlsplit(origin).netloc != request.host)):
                return jsonify({"error": "İcazə verilmədi."}), 403
        _account_request_lock.acquire()
        g.account_lock_held = True


@app.teardown_request
def release_account_request_lock(error):
    if getattr(g, "account_lock_held", False):
        g.account_lock_held = False
        _account_request_lock.release()


@app.before_request
def validate_api_input():
    if request.method != "POST":
        return None
    path = request.path
    if path not in ("/api/register", "/api/login", "/api/generate-password", "/api/items") and not (
            path.startswith("/api/items/") and path.endswith("/decrypt")):
        return None
    data = request.get_json(silent=True)
    valid = isinstance(data, dict)
    if valid and path in ("/api/register", "/api/login"):
        fields = ("username", "password", "confirm_password") if path == "/api/register" else ("username", "password", "otp_code")
        valid = all(isinstance(data.get(key, ""), str) and len(data.get(key, "")) <= 1024 for key in fields)
    elif valid and path == "/api/generate-password":
        length = data.get("length", 16)
        valid = (type(length) is int and 8 <= length <= 128
                 and all(type(data.get(key, True)) is bool for key in
                         ("uppercase", "lowercase", "digits", "symbols")))
    elif valid:
        password = data.get("master_password")
        valid = isinstance(password, str) and 0 < len(password) <= 1024
        if path == "/api/items":
            payload = data.get("data")
            valid = (valid and data.get("type", "login") in ("login", "card")
                     and isinstance(payload, dict)
                     and all(isinstance(value, str) and len(value) <= 16384 for value in payload.values()))
    if not valid:
        return jsonify({"success": False, "error": "Invalid request data."}), 400


@app.errorhandler(StorageError)
def storage_unavailable(error):
    request_logger.warning("api.storage_failed", exc_info=True)
    return jsonify({"success": False, "error": "Storage operation failed. Please retry."}), 503

# Browser diagnostics accept fixed event names only, never exception text or data.
import time
from collections import deque
from threading import Lock

_client_log_times = deque()
_client_log_lock = Lock()
_client_events = frozenset({
    "page.ready", "ui.action", "browser.error", "browser.rejection",
    "network.failed", "clipboard.failed",
})


@app.route("/api/client-events", methods=["POST"])
def api_client_events():
    if request.content_length is None or request.content_length > 512:
        return "", 413
    if request.headers.get("Sec-Fetch-Site") not in (None, "same-origin"):
        return "", 403
    data = request.get_json(silent=True)
    if (not isinstance(data, dict) or not isinstance(data.get("event"), str)
            or data["event"] not in _client_events):
        return "", 400
    with _client_log_lock:
        now = time.monotonic()
        while _client_log_times and _client_log_times[0] < now - 60:
            _client_log_times.popleft()
        if len(_client_log_times) >= 60:
            return "", 429
        _client_log_times.append(now)
    client_logger.log(30 if data["event"].endswith(("error", "rejection", "failed")) else 20,
               "client." + data["event"])
    return "", 204


def get_auth_token(*, allow_cookie=True):
    """Prefer an explicit bearer token, optionally accepting the session cookie."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:].strip()
    if allow_cookie:
        return request.cookies.get("sifrx_token")
    return None


def get_authenticated_user():
    """Resolve the current user from the request's session token."""
    return auth.get_session_user(get_auth_token())


@app.route("/api/settings", methods=["GET"])
@app.route("/api/settings/<action>", methods=["POST"])
def api_settings(action=None):
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Hesaba daxil olun."}), 401
    try:
        if request.method == "GET":
            return jsonify(account_settings.status(user))
        # Explicit bearer auth and JSON prevent cookie-only cross-site mutations.
        token = get_auth_token(allow_cookie=False)
        if not token or auth.get_session_user(token) != user:
            return jsonify({"error": "İcazə verilmədi."}), 403
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or any(not isinstance(value, str) or len(value) > 1024 for value in data.values()):
            return jsonify({"error": "Form məlumatları düzgün deyil."}), 400
        password = data.get("current_password", "")
        code = data.get("otp_code", "").strip()
        payload = {"success": True}
        if action == "password":
            account_settings.change_password(user, password, data.get("new_password", ""),
                                             data.get("confirm_password", ""), code)
        elif action == "delete-account":
            account_settings.delete_account(user, password, code, data.get("confirmation", ""))
        elif action == "2fa-setup":
            payload.update(account_settings.begin_two_factor(user, password, token))
        elif action == "2fa-enable":
            payload["recovery_codes"] = account_settings.enable_two_factor(user, password, code, token)
        elif action == "2fa-disable":
            account_settings.disable_two_factor(user, password, code)
        else:
            return jsonify({"error": "Əməliyyat tapılmadı."}), 404
        response = jsonify(payload)
        if action != "2fa-setup":
            response.delete_cookie("sifrx_token")
        return response
    except RateLimitError as error:
        return jsonify({"error": str(error)}), 429
    except AuthError as error:
        return jsonify({"error": str(error)}), 400
    except InvalidKeyOrTamperedDataError:
        return jsonify({"error": "Vault məlumatlarından biri açıla bilmədi. Şifrə dəyişdirilmədi."}), 409
    except Exception:
        settings_logger.error("settings.operation_failed", exc_info=True)
        return jsonify({"error": "Əməliyyat tamamlanmadı. Yenidən cəhd edin."}), 503


@app.after_request
def protect_sensitive_responses(response):
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json(force=True, silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    confirm_password = data.get("confirm_password", "")

    try:
        result = auth.register(username, password, confirm_password)
        return jsonify({"success": True, "message": "Qeydiyyat uğurla tamamlandı.", "username": result["username"]}), 201
    except AuthError as e:
        request_logger.warning("api.operation_failed", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 400
    except StorageError:
        raise
    except Exception as e:
        request_logger.warning("api.operation_failed", exc_info=True)
        return jsonify({"success": False, "error": "Operation failed. Please retry."}), 500


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(force=True, silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"success": False, "error": "Form məlumatları düzgün deyil."}), 400
    username = data.get("username", "")
    password = data.get("password", "")

    try:
        if not all(isinstance(value, str) for value in (username, password, data.get("otp_code", ""))):
            return jsonify({"error": "Form məlumatları düzgün deyil."}), 400
        token, user_info = auth.login(username, password, data.get("otp_code", "").strip())
        resp = jsonify({"success": True, "token": token, "username": user_info["username"]})
        resp.set_cookie("sifrx_token", token, httponly=True, samesite="Lax")
        return resp, 200
    except TwoFactorRequired as e:
        return jsonify({"success": False, "requires_2fa": True, "error": str(e)}), 401
    except RateLimitError as e:
        return jsonify({"success": False, "error": str(e)}), 429
    except AuthError as e:
        request_logger.warning("api.operation_failed", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 401
    except StorageError:
        raise
    except Exception as e:
        request_logger.warning("api.operation_failed", exc_info=True)
        return jsonify({"success": False, "error": "Giriş tamamlanmadı. Yenidən cəhd edin."}), 500


@app.route("/api/logout", methods=["POST"])
def api_logout():
    token = get_auth_token()
    if token:
        auth.logout(token)
    resp = jsonify({"success": True})
    resp.delete_cookie("sifrx_token")
    return resp, 200


@app.route("/api/me", methods=["GET"])
def api_me():
    user = get_authenticated_user()
    if not user:
        return jsonify({"authenticated": False}), 401
    return jsonify({"authenticated": True, "username": user})


@app.route("/api/generate-password", methods=["POST"])
def api_generate_password():
    """Mərkəzi Şifrələmə Motoru vasitəsilə güclü şifrə yaradır."""
    data = request.get_json(force=True, silent=True) or {}
    length = int(data.get("length", 16))
    use_upper = bool(data.get("uppercase", True))
    use_lower = bool(data.get("lowercase", True))
    use_digits = bool(data.get("digits", True))
    use_symbols = bool(data.get("symbols", True))

    pwd = CentralCryptoEngine.generate_password(
        length=length,
        use_upper=use_upper,
        use_lower=use_lower,
        use_digits=use_digits,
        use_symbols=use_symbols
    )
    return jsonify({"password": pwd})


@app.route("/api/items", methods=["GET"])
def api_list_items():
    """İstifadəçinin bulud qovluğundakı .sifrx fayllarının siyahısını qaytarır."""
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "İcazə verilmədi."}), 401

    try:
        items = storage.list_items(user)
        return jsonify({"items": items})
    except StorageError:
        raise
    except Exception as e:
        request_logger.warning("api.operation_failed", exc_info=True)
        return jsonify({"error": "Operation failed. Please retry."}), 500


@app.route("/api/items", methods=["POST"])
def api_create_item():
    """
    Yeni login və ya kart məlumatını qəbul edir,
    Mərkəzi Şifrələmə Motorunda .sifrx formatında şifrələyir və
    istifadəçinin bulud qovluğunda saxlayır.
    """
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "İcazə verilmədi."}), 401

    req_data = request.get_json(force=True, silent=True) or {}
    master_password = req_data.get("master_password")
    item_type = req_data.get("type", "login")
    payload = req_data.get("data", {})

    if not master_password:
        return jsonify({"error": "Şifrələmə üçün master şifrə tələb olunur."}), 400

    title = payload.get("title", "").strip() or ("Adsız Giriş" if item_type == "login" else "Adsız Kart")

    try:
        # Mərkəzi motor vasitəsilə şifrələnmə
        meta = {
            "type": item_type,
            "title": title
        }
        sifrx_package = CentralCryptoEngine.encrypt_to_sifrx(payload, master_password, meta=meta)

        # Bulud qovluğuna yazılma
        item_id = storage.save_item(user, sifrx_package)

        return jsonify({"success": True, "id": item_id, "message": "Məlumat .sifrx formatında şifrələnərək saxlanıldı."}), 201
    except CryptoError as e:
        request_logger.warning("api.operation_failed", exc_info=True)
        return jsonify({"error": "Operation failed. Please retry."}), 500
    except StorageError:
        raise
    except Exception as e:
        request_logger.warning("api.operation_failed", exc_info=True)
        return jsonify({"error": "Operation failed. Please retry."}), 500


@app.route("/api/items/<item_id>/decrypt", methods=["POST"])
def api_decrypt_item(item_id):
    """
    İstifadəçinin qovluğundakı .sifrx faylını Mərkəzi Şifrələmə Motoru vasitəsilə deşifrələyir.
    """
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "İcazə verilmədi."}), 401

    req_data = request.get_json(force=True, silent=True) or {}
    master_password = req_data.get("master_password")
    if not master_password:
        return jsonify({"error": "Deşifrələmə üçün master şifrə tələb olunur."}), 400

    sifrx_package = storage.get_item(user, item_id)
    if not sifrx_package:
        return jsonify({"error": "Məlumat tapılmadı."}), 404

    try:
        # Mərkəzi motor vasitəsilə deşifrələnmə
        decrypted = CentralCryptoEngine.decrypt_from_sifrx(sifrx_package, master_password)
        return jsonify({"success": True, "item": decrypted["payload"], "meta": decrypted["meta"]})
    except InvalidKeyOrTamperedDataError as e:
        request_logger.warning("api.operation_failed", exc_info=True)
        return jsonify({"error": str(e)}), 403
    except CryptoError as e:
        request_logger.warning("api.operation_failed", exc_info=True)
        return jsonify({"error": "Operation failed. Please retry."}), 500
    except StorageError:
        raise
    except Exception as e:
        request_logger.warning("api.operation_failed", exc_info=True)
        return jsonify({"error": "Operation failed. Please retry."}), 500


@app.route("/api/items/<item_id>", methods=["DELETE"])
def api_delete_item(item_id):
    """Bulud qovluğundan .sifrx faylını silir."""
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "İcazə verilmədi."}), 401

    deleted = storage.delete_item(user, item_id)
    if not deleted:
        return jsonify({"error": "Fayl tapılmadı və ya silinə bilmədi."}), 404

    return jsonify({"success": True, "message": "Məlumat silindi."})
