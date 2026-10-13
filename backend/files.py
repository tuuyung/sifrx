"""Bounded text-file validation and process-local resource controls."""
import base64
import binascii
import csv
import io
import json
import math
import time
import unicodedata
from collections import deque
from threading import Lock

MAX_FILE_BYTES = 1024 * 1024
MAX_UPLOAD_BODY = 1536 * 1024
MAX_PACKAGE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 10 * MAX_FILE_BYTES
MAX_FILES = 50
PREVIEW_CHARS = 65536
csv.field_size_limit(MAX_FILE_BYTES)


class FileValidationError(ValueError):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


class FileRateLimitError(Exception):
    def __init__(self, retry_after):
        self.retry_after = retry_after


class FileRequestLimiter:
    """Bound account keys and discard idle windows; never retain tokens."""
    def __init__(self):
        self.windows = {}
        self.lock = Lock()

    def check(self, account_id, operation):
        now = time.monotonic()
        with self.lock:
            for key in list(self.windows):
                times = self.windows[key]
                while times and times[0] <= now - 60:
                    times.popleft()
                if not times:
                    del self.windows[key]
            keys = [((operation, account_id), 5 if operation == "upload" else 20)]
            if operation == "upload":
                keys.append(((operation, "global"), 30))
            if len(self.windows) + sum(key not in self.windows for key, _ in keys) > 10000:
                raise FileRateLimitError(60)
            for key, limit in keys:
                times = self.windows.get(key, ())
                if len(times) >= limit:
                    raise FileRateLimitError(max(1, math.ceil(times[0] + 60 - now)))
            for key, _ in keys:
                self.windows.setdefault(key, deque()).append(now)


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate field")
            result[key] = value
        return result
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError):
        raise FileValidationError("Form məlumatları düzgün deyil.") from None
    if not isinstance(data, dict):
        raise FileValidationError("Form məlumatları düzgün deyil.")
    return data


def validate_filename(name):
    if not isinstance(name, str):
        raise FileValidationError("Fayl adı düzgün deyil.")
    try:
        valid = (0 < len(name) <= 120 and len(name.encode("utf-8")) <= 240
                 and name == name.strip() and not name.startswith(".")
                 and not name.endswith(".")
                 and all(unicodedata.category(c)[0] in "LNM" or c in " ._-" for c in name))
    except UnicodeError:
        valid = False
    stem = unicodedata.normalize("NFKC", name.split(".", 1)[0]).upper().rstrip(" ")
    reserved = {"CON", "PRN", "AUX", "NUL"} | {f"{prefix}{i}" for prefix in ("COM", "LPT") for i in range(1, 10)}
    if not valid or stem in reserved or name.rsplit(".", 1)[-1].lower() not in ("txt", "csv") or "." not in name:
        raise FileValidationError("Yalnız təhlükəsiz adlı .txt və .csv faylları qəbul edilir.")
    return name


def decode_content(encoded):
    if not isinstance(encoded, str):
        raise FileValidationError("Fayl məlumatları düzgün deyil.")
    if len(encoded) > 4 * ((MAX_FILE_BYTES + 2) // 3):
        raise FileValidationError("Fayl həcmi 1 MiB-dan çox ola bilməz.", 413)
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise FileValidationError("Fayl məlumatları düzgün deyil.") from None
    if len(raw) > MAX_FILE_BYTES:
        raise FileValidationError("Fayl həcmi 1 MiB-dan çox ola bilməz.", 413)
    return raw


def validate_text(raw, filename):
    encoding = ("utf-16-le" if raw.startswith(b"\xff\xfe") else
                "utf-16-be" if raw.startswith(b"\xfe\xff") else
                "utf-8-sig" if raw.startswith(b"\xef\xbb\xbf") else "utf-8")
    try:
        text = raw.decode("utf-16" if encoding.startswith("utf-16") else encoding, errors="strict")
    except UnicodeError:
        raise FileValidationError("UTF-8 və ya BOM işarəli UTF-16 mətn faylı tələb olunur.") from None
    if any(unicodedata.category(c) == "Cc" and c not in "\t\r\n" for c in text):
        raise FileValidationError("İkili məlumat və idarəetmə simvolları qəbul edilmir.")
    if filename.lower().endswith(".csv"):
        validate_csv(text)
    return encoding, text


def validate_csv(text):
    # Check every supported interpretation, not a sniffed dialect that can hide
    # formula cells. Alternate dialects use permissive standard double quoting.
    for separator in (",", ";", "\t"):
        try:
            for row_number, row in enumerate(csv.reader(io.StringIO(text, newline=""), delimiter=separator)):
                if row_number >= 50000 or len(row) > 1024:
                    raise FileValidationError("CSV maksimum 50000 sətir və 1024 sütun ola bilər.")
                for cell in row:
                    normalized = unicodedata.normalize("NFKC", cell)
                    # Walk once: repeatedly slicing a long format-character
                    # prefix would make a size-bounded input quadratic in CPU.
                    index = 0
                    while index < len(normalized) and (normalized[index].isspace()
                            or unicodedata.category(normalized[index]) == "Cf"):
                        index += 1
                    formula = index < len(normalized) and normalized[index] in "=+-@"
                    if formula or normalized.lstrip(" ").startswith(("\t", "\r", "\n")):
                        raise FileValidationError("CSV-də düstur kimi başlayan xanalar qəbul edilmir.")
        except csv.Error:
            raise FileValidationError("CSV məlumatlarını yoxlamaq mümkün olmadı.") from None


def validate_upload(data):
    if set(data) != {"filename", "content_base64", "master_password"}:
        raise FileValidationError("Form məlumatları düzgün deyil.")
    password = data["master_password"]
    if not isinstance(password, str) or not 0 < len(password) <= 1024:
        raise FileValidationError("Master şifrə tələb olunur.")
    filename = validate_filename(data["filename"])
    raw = decode_content(data["content_base64"])
    encoding, _ = validate_text(raw, filename)
    return {"kind": "file", "filename": filename, "encoding": encoding,
            "size_bytes": len(raw), "content_base64": base64.b64encode(raw).decode("ascii")}


def open_file_payload(payload):
    if not isinstance(payload, dict) or payload.get("kind") != "file":
        raise FileValidationError("Fayl tapılmadı.", 404)
    filename = validate_filename(payload.get("filename"))
    raw = decode_content(payload.get("content_base64"))
    encoding, text = validate_text(raw, filename)
    if type(payload.get("size_bytes")) is not int or payload["size_bytes"] != len(raw) or payload.get("encoding") != encoding:
        raise FileValidationError("Fayl məlumatları zədələnib.", 409)
    return raw, text


def upload_policy(items):
    files = [item for item in items if item["type"] == "file"]
    return {"max_file_bytes": MAX_FILE_BYTES, "max_total_bytes": MAX_TOTAL_BYTES,
            "max_files": MAX_FILES, "used_bytes": sum(item["size_bytes"] for item in files), "count": len(files)}
