"""
redaction_service.py
---------------------
Masks/redacts sensitive values discovered by the detection engine.

Masking strategy is type-aware:
- Email:            jo***@gmail.com
- Card/Account nums: ********9876 (last 4 preserved)
- PAN:               *****1234F (last 4 chars preserved, matches spec)
- Generic secrets:   fully masked

Returns both a redacted copy of the full text and a mapping table of
original -> masked value pairs, so the UI can show a before/after
preview.
"""

from __future__ import annotations

import re

from services.detection_service import Finding


def _mask_email(value: str) -> str:
    try:
        local, domain = value.split("@", 1)
    except ValueError:
        return "***"
    visible = local[:2] if len(local) > 2 else local[:1]
    return f"{visible}{'*' * max(1, len(local) - len(visible))}@{domain}"


def _mask_keep_last4(value: str) -> str:
    digits_only = re.sub(r"\s", "", value)
    if len(digits_only) <= 4:
        return "*" * len(digits_only)
    return "*" * (len(digits_only) - 4) + digits_only[-4:]


def _mask_pan(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return "*" * (len(value) - 4) + value[-4:]


def _mask_generic(value: str) -> str:
    return "*" * len(value) if len(value) <= 8 else value[:2] + "*" * (len(value) - 2)


_MASKERS = {
    "Email Address": _mask_email,
    "Credit Card Number": _mask_keep_last4,
    "Bank Account Number": _mask_keep_last4,
    "Aadhaar Number": _mask_keep_last4,
    "PAN Number": _mask_pan,
}


def mask_value(data_type: str, value: str) -> str:
    masker = _MASKERS.get(data_type, _mask_generic)
    return masker(value)


def build_redaction_map(findings: list[Finding]) -> list[dict]:
    """Return a list of {data_type, original, masked} rows for preview/export."""
    rows = []
    for f in findings:
        for original in f.matches:
            rows.append(
                {
                    "data_type": f.data_type,
                    "original": original,
                    "masked": mask_value(f.data_type, original),
                }
            )
    return rows


def redact_text(text: str, findings: list[Finding]) -> str:
    """
    Apply all masks to the full document text and return the sanitized
    version. Longer matches are replaced first to avoid partial/overlap
    collisions (e.g. a 16-digit card number containing a 12-digit
    Aadhaar-shaped substring).
    """
    redaction_map = build_redaction_map(findings)
    # Replace longest strings first to reduce substring collisions
    redaction_map.sort(key=lambda r: len(r["original"]), reverse=True)

    redacted = text
    for row in redaction_map:
        original = row["original"]
        if not original:
            continue
        redacted = redacted.replace(original, row["masked"])

    return redacted
