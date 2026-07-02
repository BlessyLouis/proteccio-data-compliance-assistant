"""
gemini_service.py
-------------------
Thin wrapper around Google's Gemini API for:
1. Generating an executive AI summary of detection/compliance findings.
2. Answering document-chat questions (used by rag/rag_engine.py as the
   generation step after retrieval).

Kept isolated so the rest of the app never imports google.generativeai
directly — makes it trivial to swap providers later.
"""

from __future__ import annotations

import json
import os
import re
from typing import Optional

import google.generativeai as genai

from utils.logger import get_logger

logger = get_logger(__name__)

_MODEL_NAME = "gemini-2.5-flash"
_configured = False


def configure_gemini(api_key: Optional[str] = None) -> bool:
    """
    Configure the Gemini client. Returns True if a usable key was found
    (either passed explicitly or via GEMINI_API_KEY env var), else False.
    """
    global _configured
    key = api_key or os.getenv("GEMINI_API_KEY")
    if not key:
        return False
    try:
        genai.configure(api_key=key)
        _configured = True
        return True
    except Exception as exc:
        logger.error(f"Failed to configure Gemini: {exc}")
        return False


def is_configured() -> bool:
    return _configured


def _get_model():
    return genai.GenerativeModel(_MODEL_NAME)


def _extract_json(raw_text: str) -> Optional[dict]:
    """Strip markdown code fences and parse the first JSON object found."""
    cleaned = raw_text.strip()
    cleaned = re.sub(r"^```(?:json)?", "", cleaned).strip()
    cleaned = re.sub(r"```$", "", cleaned).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                return None
        return None


def generate_executive_briefing(context: str) -> Optional[dict]:
    """
    Generate a compact, bullet-capped executive briefing as structured
    JSON — designed to render as scannable cards rather than prose.

    Returns a dict with keys: executive_summary (<=3 bullets),
    key_risks (<=5), compliance_impact (<=5), immediate_actions (<=5),
    business_impact (<=3). Returns None if generation/parsing fails.
    """
    if not _configured:
        return None

    prompt = f"""
You are a senior security and compliance analyst briefing a CISO who
has 30 seconds to read this. Based on the scan results below, return
ONLY a raw JSON object (no markdown fences, no prose) with this exact
shape:

{{
  "executive_summary": ["...", "...", "..."],
  "key_risks": ["...", "...", "...", "...", "..."],
  "compliance_impact": ["...", "...", "...", "...", "..."],
  "immediate_actions": ["...", "...", "...", "...", "..."],
  "business_impact": ["...", "...", "..."]
}}

Hard limits: executive_summary max 3 items, key_risks max 5,
compliance_impact max 5, immediate_actions max 5, business_impact max 3.
Each bullet must be ONE short sentence (under 20 words). Be specific —
reference actual data types and counts from the scan results. No
generic filler, no repetition across sections.

SCAN RESULTS:
{context}
"""
    try:
        model = _get_model()
        response = model.generate_content(prompt)
        parsed = _extract_json(response.text)
        if not parsed:
            logger.warning("Could not parse executive briefing JSON from Gemini response.")
            return None

        # Enforce caps defensively even if the model overshoots.
        caps = {
            "executive_summary": 3,
            "key_risks": 5,
            "compliance_impact": 5,
            "immediate_actions": 5,
            "business_impact": 3,
        }
        for key, cap in caps.items():
            if key in parsed and isinstance(parsed[key], list):
                parsed[key] = parsed[key][:cap]
            else:
                parsed[key] = []
        return parsed
    except Exception as exc:
        logger.error(f"Gemini executive briefing generation failed: {exc}")
        return None


def generate_document_intelligence(text_sample: str, findings_context: str) -> Optional[dict]:
    """
    Generate a lightweight document-intelligence profile: a 2-3 sentence
    summary, a document category, and 3-6 key topics. Returns None on
    failure so callers can fall back to heuristics.
    """
    if not _configured:
        return None

    prompt = f"""
Analyze the document excerpt below and return ONLY a raw JSON object
(no markdown fences, no prose) with this exact shape:

{{
  "summary": "2-3 sentence plain-language summary of what this document is",
  "category": "one short label, e.g. 'Financial Record', 'HR Document', 'Contract', 'Customer Data Export', 'Technical Log', 'Business Correspondence'",
  "key_topics": ["topic1", "topic2", "topic3"]
}}

key_topics must have between 3 and 6 short (1-3 word) items.

DETECTED SENSITIVE DATA CONTEXT:
{findings_context}

DOCUMENT EXCERPT:
{text_sample[:4000]}
"""
    try:
        model = _get_model()
        response = model.generate_content(prompt)
        parsed = _extract_json(response.text)
        if not parsed or "summary" not in parsed:
            logger.warning("Could not parse document intelligence JSON from Gemini response.")
            return None
        parsed["key_topics"] = parsed.get("key_topics", [])[:6]
        return parsed
    except Exception as exc:
        logger.error(f"Gemini document intelligence generation failed: {exc}")
        return None


def generate_executive_summary(context: str) -> str:
    """
    Legacy long-form executive summary (kept for PDF report export,
    where a fuller narrative is appropriate). The in-app Compliance
    Report page uses generate_executive_briefing() instead for a
    scannable card layout.
    """
    if not _configured:
        return (
            "⚠️ Gemini API key not configured. Add GEMINI_API_KEY to your .env file "
            "to enable AI-generated executive summaries."
        )

    prompt = f"""
You are a senior data security and compliance analyst. Based on the
scan results below, produce a professional report with EXACTLY these
six sections, using Markdown headers (##):

## Executive Summary
## Compliance Observations
## Security Risks
## Business Impact
## Remediation Steps
## Priority Recommendations

Be concise, specific, and avoid generic filler. Reference the actual
data types and counts provided. Write for a non-technical executive
audience where possible, but be precise about technical risks.

SCAN RESULTS:
{context}
"""
    try:
        model = _get_model()
        response = model.generate_content(prompt)
        return response.text
    except Exception as exc:
        logger.error(f"Gemini summary generation failed: {exc}")
        return f"⚠️ Could not generate AI summary: {exc}"


def generate_chat_response(question: str, retrieved_chunks: list[str], chat_history: Optional[list] = None) -> str:
    """
    Generate a RAG chat response given the user's question and the
    top retrieved document chunks. chat_history is a list of
    {"role": "user"/"assistant", "content": str} dicts for context.
    """
    if not _configured:
        return (
            "⚠️ Gemini API key not configured. Add GEMINI_API_KEY to your .env file "
            "to enable document chat."
        )

    context_block = "\n\n---\n\n".join(retrieved_chunks) if retrieved_chunks else "(no relevant context retrieved)"

    history_block = ""
    if chat_history:
        for turn in chat_history[-6:]:  # keep last 6 turns for brevity
            role = "User" if turn["role"] == "user" else "Assistant"
            history_block += f"{role}: {turn['content']}\n"

    prompt = f"""
You are Proteccio Data's document assistant. Answer the user's question
using ONLY the provided document context. If the answer is not present
in the context, say so honestly instead of guessing. Be concise and
reference specific findings where relevant (e.g. counts of sensitive
data types).

CONVERSATION HISTORY:
{history_block}

DOCUMENT CONTEXT:
{context_block}

USER QUESTION:
{question}
"""
    try:
        model = _get_model()
        response = model.generate_content(prompt)
        return response.text
    except Exception as exc:
        logger.error(f"Gemini chat generation failed: {exc}")
        return f"⚠️ Could not generate response: {exc}"
