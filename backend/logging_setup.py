"""Structured operational logging. Never pass user data to log messages."""

import functools
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import sys
import time
import traceback
import uuid
from datetime import datetime, timezone

from flask import g, has_request_context, request


LOG_CATEGORIES = {
    "http": "requests",
    "auth": "authentication",
    "storage": "storage",
    "crypto_engine": "crypto",
    "account_settings": "settings",
    "client": "frontend",
}
LOG_FILES = (*dict.fromkeys(LOG_CATEGORIES.values()), "application", "errors")


def record_category(record):
    component = record.name.split(".")[1:2]
    return LOG_CATEGORIES.get(component[0] if component else "", "application")


class CategoryFilter(logging.Filter):
    def __init__(self, category):
        super().__init__()
        self.category = category

    def filter(self, record):
        if self.category == "errors":
            return record.levelno >= logging.ERROR
        return record_category(record) == self.category


class JsonFormatter(logging.Formatter):
    def format(self, record):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "category": record_category(record),
            "event": record.getMessage(),
        }
        if has_request_context():
            entry["request_id"] = getattr(g, "request_id", None)
            entry["method"] = request.method
            # Route templates avoid recording user-controlled paths and queries.
            entry["route"] = request.url_rule.rule if request.url_rule else "unmatched"
        entry.update(getattr(record, "fields", {}))
        if record.exc_info:
            entry["exception_type"] = record.exc_info[0].__name__
            entry["frames"] = [
                {"file": Path(frame.filename).name, "line": frame.lineno, "function": frame.name}
                for frame in traceback.extract_tb(record.exc_info[2])
            ]
        return json.dumps(entry, ensure_ascii=False)


def configure_logging():
    logger = logging.getLogger("sifrx")
    if logger.handlers:
        return logger
    level = os.environ.get("SIFRX_LOG_LEVEL", "INFO").upper()
    if level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
        raise ValueError("SIFRX_LOG_LEVEL must be DEBUG, INFO, WARNING, ERROR or CRITICAL")
    log_dir = Path(os.environ.get("SIFRX_LOG_DIR", str(Path(__file__).resolve().parent.parent / "logs")))
    log_dir.mkdir(parents=True, exist_ok=True)
    max_bytes = int(os.environ.get("SIFRX_LOG_MAX_BYTES", "5242880"))
    backups = int(os.environ.get("SIFRX_LOG_BACKUP_COUNT", "5"))
    if max_bytes <= 0 or backups < 1:
        raise ValueError("Log size and backup count must be positive")
    handlers = []
    for category in LOG_FILES:
        handler = RotatingFileHandler(log_dir / (category + ".jsonl"), maxBytes=max_bytes,
                                      backupCount=backups, encoding="utf-8")
        handler.addFilter(CategoryFilter(category))
        handlers.append(handler)
    if os.environ.get("SIFRX_LOG_CONSOLE", "true").lower() in ("true", "1"):
        handlers.append(logging.StreamHandler())
    for handler in handlers:
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    # Werkzeug access logs include raw URLs; Flask hooks supply safe access logs.
    logging.getLogger("werkzeug").disabled = True
    logger.info("logging.ready")
    return logger


def logged_operation(func):
    """Log operation outcomes and timing without inspecting arguments/results."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        logger = logging.getLogger("sifrx." + func.__module__.rsplit(".", 1)[-1])
        started = time.perf_counter()
        event = func.__qualname__
        logger.debug(event + ".started")
        try:
            result = func(*args, **kwargs)
        except Exception:
            logger.warning(event + ".failed", exc_info=True)
            raise
        fields = {"duration_ms": round((time.perf_counter() - started) * 1000, 2)}
        if isinstance(result, bool):
            fields["outcome"] = result
        elif result is None:
            fields["outcome"] = "empty"
        logger.info(event + ".completed", extra={"fields": fields})
        return result
    return wrapper


def install_request_logging(app):
    logger = logging.getLogger("sifrx.http")

    @app.before_request
    def begin_request():
        g.request_id = uuid.uuid4().hex
        g.request_started = time.perf_counter()
        logger.debug("request.started")

    @app.after_request
    def finish_request(response):
        response.headers["X-Request-ID"] = g.request_id
        level = logging.ERROR if response.status_code >= 500 else (
            logging.WARNING if response.status_code >= 400 else logging.INFO)
        logger.log(level, "request.completed", extra={"fields": {
            "status": response.status_code,
            "duration_ms": round((time.perf_counter() - g.request_started) * 1000, 2),
        }})
        return response

    # Replace Flask's default exception logger, which prints exception messages.
    def log_exception(exc_info):
        logger.error("request.unhandled_exception", exc_info=exc_info)
    app.log_exception = log_exception

    previous_hook = sys.excepthook
    def uncaught(exc_type, exc, tb):
        if issubclass(exc_type, KeyboardInterrupt):
            previous_hook(exc_type, exc, tb)
        else:
            logging.getLogger("sifrx.runtime").critical("runtime.unhandled_exception",
                                                       exc_info=(exc_type, exc, tb))
    sys.excepthook = uncaught
