"""
sidebar.py
-----------
Sidebar navigation and system status. The Gemini API key is loaded
silently from the environment (.env / platform secrets) at startup —
it is never entered, displayed, or editable in the UI. The sidebar
only ever shows connection status, which is what an enterprise
security operator expects to see (system health, not credentials).
"""

from __future__ import annotations

import streamlit as st

from components.ui_helpers import render_brand_header, status_block
from services import gemini_service

PAGES = [
    "Upload Document",
    "Detection Dashboard",
    "Compliance Report",
    "Redaction Center",
    "Document Chat",
    "Audit Logs",
    "About Platform",
]

PAGE_ICONS = {
    "Upload Document": "📤",
    "Detection Dashboard": "🛡️",
    "Compliance Report": "📋",
    "Redaction Center": "🕶️",
    "Document Chat": "💬",
    "Audit Logs": "🧾",
    "About Platform": "ℹ️",
}


def render_sidebar() -> str:
    with st.sidebar:
        render_brand_header()

        gemini_ready = gemini_service.is_configured()

        status_rows = [
            ("AI Engine", "Online" if gemini_ready else "Offline", "green" if gemini_ready else "red"),
            ("Detection Engine", "Active", "green"),
            ("Compliance Engine", "Ready", "green"),
            ("RAG Engine", "Online" if gemini_ready else "Degraded", "green" if gemini_ready else "amber"),
        ]
        status_block("System Status", status_rows)

        if not gemini_ready:
            st.caption("⚠️ Set GEMINI_API_KEY in your .env file to enable AI summaries & chat.")

        st.markdown("#### Navigation")
        selected = st.radio(
            "Navigation",
            PAGES,
            format_func=lambda p: f"{PAGE_ICONS.get(p, '')}  {p}",
            label_visibility="collapsed",
        )

        st.markdown("---")

        doc = st.session_state.get("current_document")
        history = st.session_state.get("history", [])
        risk = st.session_state.get("risk_assessment")

        st.markdown("#### Quick Stats")
        st.caption(f"📄 Documents Scanned:  **{len(history)}**")
        if risk is not None:
            st.caption(f"🔎 Sensitive Items Found:  **{risk.total_items}**")
            st.caption(f"📊 Compliance Score:  **{risk.compliance_score}/100**")
            st.caption(f"⚠️ Risk Level:  **{risk.classification}**")
        if doc:
            st.caption(f"📎 Active Document: **{doc.filename}**")

        st.markdown("---")
        if st.button("🗑️ Reset Session", use_container_width=True):
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()

        st.caption("Proteccio Data v2.0 · Enterprise Preview")

    return selected
