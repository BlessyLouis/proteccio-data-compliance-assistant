"""
detection_service.py
---------------------
Core sensitive-data detection engine.

Design:
- Each detector is a `DetectionRule` (regex-based) or a custom function
  (for entropy-based secret detection), registered in DETECTION_RULES.
- `scan_text()` runs every rule against the input text and returns a
  list of `Finding` objects: type, matched values, count, confidence,
  and risk contribution (used later by the risk engine).
- Designed to be reusable: works on PDF/TXT extracted text as well as
  CSV data flattened to text.

This module intentionally has NO Streamlit imports — it is pure logic,
which keeps it independently testable and reusable.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class DetectionRule:
    name: str
    category: str  # e.g. "PII", "Financial", "Credentials", "Confidential"
    pattern: Optional[re.Pattern]
    base_confidence: float  # 0.0 - 1.0
    risk_weight: int  # points contributed per unique finding (capped in risk engine)
    validator: Optional[Callable[[str], bool]] = None
    description: str = ""


@dataclass
class Finding:
    data_type: str
    category: str
    matches: list = field(default_factory=list)
    count: int = 0
    confidence: float = 0.0
    risk_weight: int = 0
    description: str = ""


# ---------------------------------------------------------------------------
# Validators (extra checks beyond regex to reduce false positives)
# ---------------------------------------------------------------------------

def _luhn_check(number: str) -> bool:
    """Luhn algorithm check for credit-card-like numbers."""
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if len(digits) < 12:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string; used to flag random-looking secrets."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


# ---------------------------------------------------------------------------
# Regex-based detection rules
# ---------------------------------------------------------------------------

DETECTION_RULES: list[DetectionRule] = [
    DetectionRule(
        name="Aadhaar Number",
        category="PII",
        pattern=re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"),
        base_confidence=0.75,
        risk_weight=40,
        description="12-digit Indian national ID number.",
    ),
    DetectionRule(
        name="PAN Number",
        category="PII",
        pattern=re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
        base_confidence=0.9,
        risk_weight=30,
        description="Indian Permanent Account Number (tax ID).",
    ),
    DetectionRule(
        name="Email Address",
        category="PII",
        pattern=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        base_confidence=0.95,
        risk_weight=10,
        description="Email address.",
    ),
    DetectionRule(
        name="Phone Number",
        category="PII",
        pattern=re.compile(r"\b(?:\+?91[-\s]?)?[6-9]\d{9}\b"),
        base_confidence=0.7,
        risk_weight=15,
        description="Indian mobile phone number.",
    ),
    DetectionRule(
        name="Credit Card Number",
        category="Financial",
        pattern=re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
        base_confidence=0.6,
        risk_weight=50,
        validator=_luhn_check,
        description="Credit/debit card number (validated via Luhn algorithm).",
    ),
    DetectionRule(
        name="Bank Account Number",
        category="Financial",
        pattern=re.compile(r"\b\d{9,18}\b"),
        base_confidence=0.4,
        risk_weight=35,
        description="Numeric string matching typical bank account length (9-18 digits).",
    ),
    DetectionRule(
        name="IFSC Code",
        category="Financial",
        pattern=re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),
        base_confidence=0.9,
        risk_weight=20,
        description="Indian bank IFSC routing code.",
    ),
    DetectionRule(
        name="Generic API Key",
        category="Credentials",
        pattern=re.compile(r"\b(?:api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?", re.IGNORECASE),
        base_confidence=0.85,
        risk_weight=60,
        description="Generic API key assignment pattern.",
    ),
    DetectionRule(
        name="AWS Access Key",
        category="Credentials",
        pattern=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        base_confidence=0.97,
        risk_weight=70,
        description="AWS Access Key ID.",
    ),
    DetectionRule(
        name="Google API Key",
        category="Credentials",
        pattern=re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        base_confidence=0.97,
        risk_weight=65,
        description="Google Cloud / Gemini API key.",
    ),
    DetectionRule(
        name="JWT Token",
        category="Credentials",
        pattern=re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
        base_confidence=0.9,
        risk_weight=55,
        description="JSON Web Token (JWT).",
    ),
    DetectionRule(
        name="Password Field",
        category="Credentials",
        pattern=re.compile(r"\b(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?([^\s'\"]{4,})['\"]?", re.IGNORECASE),
        base_confidence=0.8,
        risk_weight=55,
        description="Hardcoded password assignment.",
    ),
    DetectionRule(
        name="Access / Bearer Token",
        category="Credentials",
        pattern=re.compile(r"\b(?:access[_-]?token|bearer)['\"]?\s*[:=]?\s*['\"]?([A-Za-z0-9_\-\.]{20,})['\"]?", re.IGNORECASE),
        base_confidence=0.75,
        risk_weight=55,
        description="OAuth/bearer access token.",
    ),
    DetectionRule(
        name="Employee ID",
        category="Internal",
        pattern=re.compile(r"\bEMP[-_]?\d{3,8}\b", re.IGNORECASE),
        base_confidence=0.7,
        risk_weight=15,
        description="Internal employee identifier.",
    ),
    DetectionRule(
        name="Confidential Keyword",
        category="Confidential",
        pattern=re.compile(r"\b(confidential|internal use only|do not distribute|proprietary|trade secret|classified)\b", re.IGNORECASE),
        base_confidence=0.6,
        risk_weight=20,
        description="Explicit confidentiality marker found in document.",
    ),
    DetectionRule(
        name="Internal Business Info",
        category="Confidential",
        pattern=re.compile(r"\b(quarterly revenue|merger|acquisition|salary band|internal roadmap|unreleased product)\b", re.IGNORECASE),
        base_confidence=0.5,
        risk_weight=25,
        description="Sensitive internal business terminology.",
    ),
]


def _generic_secret_entropy_scan(text: str) -> Finding:
    """
    Entropy-based detection for generic 'secret-looking' tokens that
    don't match a specific known pattern (e.g. random config values).
    Flags any standalone alphanumeric token >= 20 chars with high
    Shannon entropy (> 4.0), which is characteristic of random secrets.
    """
    candidates = re.findall(r"\b[A-Za-z0-9+/_\-]{20,}\b", text)
    high_entropy_matches = [c for c in candidates if shannon_entropy(c) > 4.0]

    return Finding(
        data_type="High-Entropy Secret",
        category="Credentials",
        matches=high_entropy_matches,
        count=len(high_entropy_matches),
        confidence=0.55,
        risk_weight=45,
        description="Randomly-generated token detected via Shannon entropy analysis (possible unclassified secret).",
    )


def scan_text(text: str) -> list[Finding]:
    """
    Run all detection rules against the given text and return a list
    of Finding objects (only for rule types with at least one match).
    """
    findings: list[Finding] = []

    for rule in DETECTION_RULES:
        raw_matches = rule.pattern.findall(text)
        # findall with capturing groups returns the group, not full match
        matches = [m if isinstance(m, str) else m[0] for m in raw_matches]

        if rule.validator:
            matches = [m for m in matches if rule.validator(m)]

        # de-duplicate while preserving order
        unique_matches = list(dict.fromkeys(matches))

        if unique_matches:
            findings.append(
                Finding(
                    data_type=rule.name,
                    category=rule.category,
                    matches=unique_matches,
                    count=len(unique_matches),
                    confidence=rule.base_confidence,
                    risk_weight=rule.risk_weight,
                    description=rule.description,
                )
            )

    entropy_finding = _generic_secret_entropy_scan(text)
    if entropy_finding.count > 0:
        findings.append(entropy_finding)

    return findings


def findings_summary_table(findings: list[Finding]) -> list[dict]:
    """Flatten findings into a list of dicts, convenient for DataFrame/export."""
    rows = []
    for f in findings:
        rows.append(
            {
                "Data Type": f.data_type,
                "Category": f.category,
                "Count": f.count,
                "Confidence": f"{f.confidence * 100:.0f}%",
                "Risk Weight": f.risk_weight,
                "Description": f.description,
            }
        )
    return rows
