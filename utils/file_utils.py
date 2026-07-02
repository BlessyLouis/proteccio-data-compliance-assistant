"""
file_utils.py
-------------
Secure file handling helpers: saving uploads to a temp/session-scoped
location, extracting text from PDF/TXT/CSV, and basic file metadata.

Security notes:
- Uploaded files are written to a per-session subfolder under
  data/uploads/<session_id>/ so concurrent users never collide.
- Filenames are sanitized before being written to disk.
- Files are never executed or eval'd; only parsed as text/PDF/CSV.
"""

from __future__ import annotations

import io
import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import pandas as pd
from PyPDF2 import PdfReader

from utils.logger import get_logger

logger = get_logger(__name__)

BASE_UPLOAD_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "uploads"
)
os.makedirs(BASE_UPLOAD_DIR, exist_ok=True)

ALLOWED_EXTENSIONS = {".pdf", ".txt", ".csv"}
MAX_FILE_SIZE_MB = 25


@dataclass
class ExtractedDocument:
    """Normalized representation of any uploaded document."""

    filename: str
    file_type: str  # "pdf" | "txt" | "csv"
    size_bytes: int
    uploaded_at: datetime
    text_content: str
    page_count: Optional[int] = None
    row_count: Optional[int] = None
    dataframe: Optional[pd.DataFrame] = None
    saved_path: str = ""
    warnings: list = field(default_factory=list)


def sanitize_filename(filename: str) -> str:
    """Strip path components and unsafe characters from a filename."""
    filename = os.path.basename(filename)
    filename = re.sub(r"[^A-Za-z0-9_.\-]", "_", filename)
    return filename or "unnamed_file"


def validate_file(uploaded_file) -> None:
    """Raise ValueError if the uploaded file fails basic validation."""
    ext = os.path.splitext(uploaded_file.name)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Unsupported file type '{ext}'. Allowed: {ALLOWED_EXTENSIONS}")

    size_mb = uploaded_file.size / (1024 * 1024)
    if size_mb > MAX_FILE_SIZE_MB:
        raise ValueError(f"File too large ({size_mb:.1f}MB). Max allowed is {MAX_FILE_SIZE_MB}MB.")


def get_session_upload_dir(session_id: str) -> str:
    path = os.path.join(BASE_UPLOAD_DIR, session_id)
    os.makedirs(path, exist_ok=True)
    return path


def _extract_pdf_text(raw_bytes: bytes, warnings: list) -> tuple[str, int]:
    """
    Extract text from a PDF. Falls back gracefully (with a warning)
    if a page has no extractable text (e.g. a scanned image page
    without OCR applied).
    """
    reader = PdfReader(io.BytesIO(raw_bytes))
    text_parts = []
    for i, page in enumerate(reader.pages):
        try:
            page_text = page.extract_text() or ""
        except Exception as exc:  # pragma: no cover - defensive
            page_text = ""
            warnings.append(f"Could not extract text from page {i + 1}: {exc}")
        if not page_text.strip():
            warnings.append(
                f"Page {i + 1} returned no extractable text "
                f"(likely a scanned/image page). OCR is recommended for full coverage."
            )
        text_parts.append(page_text)
    return "\n".join(text_parts), len(reader.pages)


def process_uploaded_file(uploaded_file, session_id: str) -> ExtractedDocument:
    """
    Validate, persist, and extract text/structure from a Streamlit
    UploadedFile object. Returns a normalized ExtractedDocument.
    """
    validate_file(uploaded_file)

    safe_name = sanitize_filename(uploaded_file.name)
    ext = os.path.splitext(safe_name)[1].lower()
    raw_bytes = uploaded_file.getvalue()
    warnings: list = []

    # Persist to session-scoped folder with a uuid prefix to avoid collisions
    unique_name = f"{uuid.uuid4().hex[:8]}_{safe_name}"
    save_dir = get_session_upload_dir(session_id)
    saved_path = os.path.join(save_dir, unique_name)
    with open(saved_path, "wb") as f:
        f.write(raw_bytes)

    page_count = None
    row_count = None
    dataframe = None

    if ext == ".pdf":
        file_type = "pdf"
        text_content, page_count = _extract_pdf_text(raw_bytes, warnings)

    elif ext == ".txt":
        file_type = "txt"
        try:
            text_content = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            text_content = raw_bytes.decode("latin-1", errors="replace")
            warnings.append("File was not valid UTF-8; decoded with fallback encoding.")

    elif ext == ".csv":
        file_type = "csv"
        try:
            dataframe = pd.read_csv(io.BytesIO(raw_bytes))
        except Exception as exc:
            raise ValueError(f"Could not parse CSV file: {exc}")
        row_count = len(dataframe)
        text_content = dataframe.to_csv(index=False)

    else:  # pragma: no cover - guarded by validate_file
        raise ValueError("Unsupported file type.")

    logger.info(f"Processed upload: {safe_name} ({file_type}, {len(raw_bytes)} bytes)")

    return ExtractedDocument(
        filename=safe_name,
        file_type=file_type,
        size_bytes=len(raw_bytes),
        uploaded_at=datetime.now(),
        text_content=text_content,
        page_count=page_count,
        row_count=row_count,
        dataframe=dataframe,
        saved_path=saved_path,
        warnings=warnings,
    )


def cleanup_session_uploads(session_id: str) -> None:
    """Remove all files for a session (called on 'clear session' action)."""
    save_dir = os.path.join(BASE_UPLOAD_DIR, session_id)
    if os.path.isdir(save_dir):
        for f in os.listdir(save_dir):
            try:
                os.remove(os.path.join(save_dir, f))
            except OSError as exc:
                logger.warning(f"Could not remove temp file {f}: {exc}")
        try:
            os.rmdir(save_dir)
        except OSError:
            pass


def human_readable_size(size_bytes: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"
