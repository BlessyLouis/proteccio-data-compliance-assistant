"""
intelligence_service.py
-------------------------
Produces the "Document Intelligence Overview" shown after upload:
an AI-generated summary, a document category, key topics, and an
entity list — replacing the raw-text-dump preview with something
that actually helps a reviewer triage the document quickly.

Design: Gemini does the heavy lifting (summary/category/topics) when
configured; if not, deterministic heuristics keep the page functional
in a degraded mode rather than showing an error. Entities are always
derived directly from the detection engine's findings (not from the
LLM) since that's the more reliable, auditable source for compliance
purposes.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from services import gemini_service
from services.detection_service import Finding

_STOPWORDS = {
    "the", "and", "for", "with", "this", "that", "from", "have", "will",
    "your", "you", "are", "was", "were", "has", "had", "not", "but",
    "all", "can", "our", "their", "they", "them", "these", "those",
    "into", "about", "such", "than", "then", "also", "any", "each",
}


@dataclass
class DocumentIntelligence:
    summary: str
    category: str
    key_topics: list = field(default_factory=list)
    entities: list = field(default_factory=list)  # [{"type": str, "value": str}]
    source: str = "heuristic"  # "ai" | "heuristic"


def _heuristic_category(text: str, findings: list[Finding]) -> str:
    lowered = text.lower()
    categories_by_keyword = [
        (("invoice", "payment", "amount due", "purchase order"), "Financial Record"),
        (("salary", "employee id", "hr", "payroll", "performance review"), "HR Document"),
        (("agreement", "contract", "terms and conditions", "party of the first part"), "Contract"),
        (("patient", "diagnosis", "medical", "treatment"), "Healthcare Record"),
        (("api", "server", "config", "database", "error", "stack trace"), "Technical Log"),
        (("dear", "regards", "sincerely", "subject:"), "Business Correspondence"),
    ]
    for keywords, label in categories_by_keyword:
        if any(k in lowered for k in keywords):
            return label

    categories_present = {f.category for f in findings}
    if "Credentials" in categories_present:
        return "Technical / Credentials Document"
    if "Financial" in categories_present:
        return "Financial Record"
    if "PII" in categories_present:
        return "Personal Data Record"
    return "General Document"


def _heuristic_summary(text: str, findings: list[Finding]) -> str:
    snippet = re.sub(r"\s+", " ", text).strip()[:220]
    finding_note = ""
    if findings:
        top_types = ", ".join(sorted({f.data_type for f in findings})[:3])
        finding_note = f" It contains detectable sensitive data including {top_types}."
    return f"{snippet}{'…' if len(text) > 220 else ''}{finding_note}"


def _heuristic_topics(text: str) -> list[str]:
    words = re.findall(r"[A-Za-z]{4,}", text.lower())
    words = [w for w in words if w not in _STOPWORDS]
    common = [w for w, _ in Counter(words).most_common(6)]
    return [w.capitalize() for w in common]


def _findings_context(findings: list[Finding]) -> str:
    if not findings:
        return "No sensitive data detected."
    return "; ".join(f"{f.data_type}: {f.count}" for f in findings)


def detect_language(text: str) -> str:
    """
    Lightweight heuristic language flagging (not a full language-ID model,
    which would be overkill here — this just distinguishes 'English /
    Latin-script' documents from ones that clearly aren't, so the metadata
    panel has something honest to show without adding a heavy dependency).
    """
    sample = text[:2000]
    if not sample.strip():
        return "Unknown"
    ascii_ratio = sum(1 for c in sample if ord(c) < 128) / len(sample)
    if ascii_ratio > 0.95:
        return "English"
    return "Non-English / Mixed Script"

def build_entities(findings: list[Finding], limit_per_type: int = 5) -> list[dict]:
    """Flatten detection findings into an entity list for the Entities tab."""
    entities = []
    for f in findings:
        for value in f.matches[:limit_per_type]:
            entities.append({"type": f.data_type, "category": f.category, "value": value})
    return entities


def generate_document_intelligence(text: str, findings: list[Finding]) -> DocumentIntelligence:
    """
    Generate the full intelligence profile for a document. Tries Gemini
    first for summary/category/topics; falls back to heuristics on any
    failure so the UI never breaks.
    """
    entities = build_entities(findings)

    if gemini_service.is_configured():
        ai_result = gemini_service.generate_document_intelligence(text, _findings_context(findings))
        if ai_result:
            return DocumentIntelligence(
                summary=ai_result.get("summary", "").strip() or _heuristic_summary(text, findings),
                category=ai_result.get("category", "").strip() or _heuristic_category(text, findings),
                key_topics=ai_result.get("key_topics") or _heuristic_topics(text),
                entities=entities,
                source="ai",
            )

    return DocumentIntelligence(
        summary=_heuristic_summary(text, findings),
        category=_heuristic_category(text, findings),
        key_topics=_heuristic_topics(text),
        entities=entities,
        source="heuristic",
    )
