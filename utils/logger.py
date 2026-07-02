"""
logger.py
---------
Centralized logging utility for Proteccio Data.

Provides a single configured logger used across the app for:
- Application diagnostics (logs/app.log)
- Audit trail events (logs/audit.log), consumed separately by the
  Audit Logs page via services.audit_service

Kept separate from audit_service because this module handles *how*
logs are written (formatting, rotation-free file handles) while
audit_service handles *what* gets logged (structured audit events).
"""

import logging
import os
from logging.handlers import RotatingFileHandler

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

APP_LOG_PATH = os.path.join(LOG_DIR, "app.log")


def get_logger(name: str = "proteccio") -> logging.Logger:
    """
    Returns a configured logger instance. Safe to call multiple times;
    handlers are only attached once per logger name to avoid duplicate
    log lines (a common Streamlit gotcha since scripts re-run on every
    interaction).
    """
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = RotatingFileHandler(
        APP_LOG_PATH, maxBytes=2_000_000, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    logger.propagate = False

    return logger
