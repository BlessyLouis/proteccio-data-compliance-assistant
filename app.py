"""
app.py
------
Main entrypoint for Proteccio Data — Sensitive Data Detection &
Compliance Assistant (Enterprise Edition).

This file wires together the sidebar navigation and the seven pages:
Upload, Detection Dashboard, Compliance Report, Redaction Center,
Document Chat, Audit Logs, About Platform.

Design intent: every page leads with KPI/status signal before detail,
mirroring enterprise security dashboards (Purview / Wiz / Falcon)
rather than a linear "form -> output" script layout. All heavy logic
(detection, risk scoring, compliance mapping, redaction, RAG,
reporting, document intelligence) lives in services/ and rag/ — this
file is UI orchestration + session-state management only.
"""

from __future__ import annotations

import uuid
from datetime import datetime

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from dotenv import load_dotenv

from components.sidebar import render_sidebar
from components.ui_helpers import (
    load_css,
    hero_section,
    section_header,
    divider_label,
    kpi_card,
    metric_card,
    risk_badge,
    category_card,
    framework_card,
    timeline_item,
    chat_bubble,
    pill,
)
from services import audit_service, gemini_service
from services.compliance_engine import generate_compliance_observations, compute_framework_scorecards
from services.detection_service import scan_text, findings_summary_table
from services.intelligence_service import generate_document_intelligence, detect_language
from services.redaction_service import build_redaction_map, redact_text
from services.report_service import build_pdf_report, build_json_report, build_csv_report
from services.risk_engine import compute_risk
from utils.file_utils import process_uploaded_file, human_readable_size
from rag.rag_engine import build_index, answer_question

load_dotenv()

st.set_page_config(
    page_title="Proteccio Data | AI Compliance Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

FILE_TYPE_ICONS = {"pdf": "📕", "txt": "📄", "csv": "📊"}


# ---------------------------------------------------------------------------
# Session state initialization
# ---------------------------------------------------------------------------

def init_session_state() -> None:
    defaults = {
        "session_id": str(uuid.uuid4()),
        "current_document": None,
        "doc_intelligence": None,
        "findings": None,
        "risk_assessment": None,
        "compliance_observations": None,
        "framework_scorecards": None,
        "ai_briefing": None,
        "rag_index": None,
        "chat_history": [],
        "history": [],  # multi-document session history (for trend charts)
        "sanitized_text": None,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

    # Gemini is configured ONLY from the environment — never from UI input.
    if not gemini_service.is_configured():
        gemini_service.configure_gemini()


init_session_state()
load_css()


# ---------------------------------------------------------------------------
# PAGE: Upload Document
# ---------------------------------------------------------------------------

def page_upload() -> None:
    hero_section(
        "AI-Powered Data Protection",
        "Sensitive Data Detection & Compliance Intelligence",
        "Upload a document to automatically detect PII, financial data, credentials, and "
        "confidential content — then classify risk and map it to compliance frameworks in seconds.",
    )

    history = st.session_state["history"]
    risk = st.session_state["risk_assessment"]

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        kpi_card("Documents Scanned", str(len(history)), icon="📄", tone="blue")
    with c2:
        kpi_card("Total Findings", str(sum(h["total_items"] for h in history)) if history else "0", icon="🔎", tone="purple")
    with c3:
        kpi_card(
            "Compliance Score",
            f"{risk.compliance_score}" if risk else "—",
            icon="✅",
            tone="green",
            unit="/100" if risk else "",
        )
    with c4:
        ai_on = gemini_service.is_configured()
        kpi_card("AI Engine Status", "Online" if ai_on else "Offline", icon="🤖", tone="green" if ai_on else "red")

    st.write("")
    divider_label("Upload a Document")

    uploaded_file = st.file_uploader(
        "Drag and drop a file here, or click to browse",
        type=["pdf", "txt", "csv"],
        help="Supported formats: PDF, TXT, CSV · Max 25MB",
    )

    if uploaded_file is not None:
        with st.spinner("Processing and analyzing document..."):
            try:
                doc = process_uploaded_file(uploaded_file, st.session_state["session_id"])
            except ValueError as exc:
                st.error(str(exc))
                return

        is_new_doc = (
            st.session_state["current_document"] is None
            or st.session_state["current_document"].saved_path != doc.saved_path
        )

        if is_new_doc:
            st.session_state["current_document"] = doc
            st.session_state["findings"] = None
            st.session_state["doc_intelligence"] = None
            st.session_state["rag_index"] = None
            st.session_state["chat_history"] = []
            st.session_state["sanitized_text"] = None
            st.session_state["ai_briefing"] = None

            audit_service.log_event(
                "UPLOAD",
                st.session_state["session_id"],
                {"filename": doc.filename, "type": doc.file_type, "size_bytes": doc.size_bytes},
            )

        st.success(f"✅  {doc.filename} uploaded successfully")

        # --- Document Overview cards ---
        divider_label("Document Overview")
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            kpi_card("File Name", doc.filename[:18] + ("…" if len(doc.filename) > 18 else ""), icon=FILE_TYPE_ICONS.get(doc.file_type, "📄"), tone="blue")
        with c2:
            kpi_card("File Size", human_readable_size(doc.size_bytes), icon="💾", tone="purple")
        with c3:
            kpi_card("Uploaded", doc.uploaded_at.strftime("%H:%M:%S"), icon="🕒", tone="amber")
        with c4:
            if doc.file_type == "pdf":
                kpi_card("Pages", str(doc.page_count), icon="📑", tone="green")
            elif doc.file_type == "csv":
                kpi_card("Rows", str(doc.row_count), icon="📊", tone="green")
            else:
                kpi_card("Type", doc.file_type.upper(), icon="📄", tone="green")

        if doc.warnings:
            with st.expander("⚠️ Extraction warnings"):
                for w in doc.warnings:
                    st.caption(f"• {w}")

        # Run scan + intelligence automatically if not yet done for this doc
        if st.session_state["findings"] is None:
            run_detection_pipeline(doc)
        if st.session_state["doc_intelligence"] is None:
            with st.spinner("Generating document intelligence..."):
                st.session_state["doc_intelligence"] = generate_document_intelligence(
                    doc.text_content, st.session_state["findings"]
                )

        intel = st.session_state["doc_intelligence"]
        findings = st.session_state["findings"]

        # --- Document Intelligence Overview (replaces raw text dump) ---
        divider_label("Document Intelligence Overview")
        tab_overview, tab_metadata, tab_entities, tab_raw = st.tabs(
            ["Overview", "Metadata", "Entities", "Raw Text"]
        )

        with tab_overview:
            col_a, col_b = st.columns([2, 1])
            with col_a:
                st.markdown(
                    f"""<div class="pc-glass">
                    <div class="pc-kpi-label">AI-Generated Summary
                    {' · <span style="color:#34d399;">AI</span>' if intel.source == 'ai' else ' · <span style="color:#8b93a7;">Heuristic</span>'}</div>
                    <div style="margin-top:8px; font-size:14px; color:#e9edf5; line-height:1.6;">{intel.summary}</div>
                    </div>""",
                    unsafe_allow_html=True,
                )
                st.write("")
                st.markdown('<div class="pc-kpi-label">Key Topics</div>', unsafe_allow_html=True)
                topic_html = " ".join(pill(t) for t in intel.key_topics) if intel.key_topics else "<span style='color:#5b6478;'>No dominant topics detected.</span>"
                st.markdown(f"<div style='margin-top:8px;'>{topic_html}</div>", unsafe_allow_html=True)
            with col_b:
                metric_card("Document Category", intel.category)
                st.write("")
                categories_found = sorted({f.category for f in findings}) if findings else []
                cat_html = " ".join(pill(c) for c in categories_found) if categories_found else "<span style='color:#5b6478;'>None detected</span>"
                st.markdown(
                    f"""<div class="pc-glass"><div class="pc-kpi-label">Sensitive Categories Found</div>
                    <div style="margin-top:8px;">{cat_html}</div></div>""",
                    unsafe_allow_html=True,
                )

        with tab_metadata:
            m1, m2, m3, m4 = st.columns(4)
            with m1:
                metric_card("Characters", f"{len(doc.text_content):,}")
            with m2:
                metric_card("Words", f"{len(doc.text_content.split()):,}")
            with m3:
                metric_card("Lines", f"{doc.text_content.count(chr(10)) + 1:,}")
            with m4:
                metric_card("Language", detect_language(doc.text_content))

        with tab_entities:
            if intel.entities:
                st.dataframe(
                    pd.DataFrame(intel.entities).rename(
                        columns={"type": "Entity Type", "category": "Category", "value": "Value"}
                    ),
                    use_container_width=True,
                    hide_index=True,
                )
            else:
                st.info("No entities detected in this document.")

        with tab_raw:
            st.caption("Raw extracted text — provided for verification only.")
            if doc.file_type == "csv" and doc.dataframe is not None:
                st.dataframe(doc.dataframe.head(20), use_container_width=True)
            else:
                st.text_area("Extracted text", doc.text_content[:5000], height=280, label_visibility="collapsed")

        st.write("")
        col_x, col_y = st.columns([1, 1])
        with col_x:
            if st.button("🛡️ View Detection Dashboard", type="primary", use_container_width=True):
                st.session_state["_nav_override"] = "Detection Dashboard"
                st.rerun()
        with col_y:
            if st.button("🔄 Re-run Detection Scan", use_container_width=True):
                run_detection_pipeline(doc, force=True)
                st.rerun()

    elif st.session_state["current_document"]:
        st.info("A document is already loaded. Upload a new file to replace it, or use the sidebar to navigate.")


def run_detection_pipeline(doc, force: bool = False) -> None:
    """Run detection + risk + compliance engines and store results in session state."""
    if not force and st.session_state["findings"] is not None:
        return

    with st.spinner("Scanning for sensitive data..."):
        findings = scan_text(doc.text_content)
        risk = compute_risk(findings)
        observations = generate_compliance_observations(findings, doc.text_content)
        scorecards = compute_framework_scorecards(observations)

    st.session_state["findings"] = findings
    st.session_state["risk_assessment"] = risk
    st.session_state["compliance_observations"] = observations
    st.session_state["framework_scorecards"] = scorecards
    st.session_state["history"].append(
        {
            "filename": doc.filename,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "risk_score": risk.score,
            "classification": risk.classification,
            "total_items": risk.total_items,
        }
    )

    audit_service.log_event(
        "DETECTION",
        st.session_state["session_id"],
        {"filename": doc.filename, "total_items": risk.total_items, "categories": risk.total_categories},
    )
    audit_service.log_event(
        "RISK_ASSESSMENT",
        st.session_state["session_id"],
        {"filename": doc.filename, "score": risk.score, "classification": risk.classification},
    )


# ---------------------------------------------------------------------------
# PAGE: Detection Dashboard (Executive Security Dashboard)
# ---------------------------------------------------------------------------

def page_dashboard() -> None:
    hero_section(
        "Executive Security Dashboard",
        "Detection & Risk Intelligence",
        "Real-time visibility into sensitive data exposure, risk posture, and document health.",
    )

    if st.session_state["current_document"] is None:
        st.warning("No document loaded yet. Go to 'Upload Document' first.")
        return

    if st.session_state["findings"] is None:
        st.info("Document loaded but not yet scanned.")
        if st.button("🔍 Run Detection Scan Now", type="primary"):
            run_detection_pipeline(st.session_state["current_document"], force=True)
            st.rerun()
        return

    findings = st.session_state["findings"]
    risk = st.session_state["risk_assessment"]

    # --- Top KPI row (6 cards) ---
    cols = st.columns(6)
    with cols[0]:
        kpi_card("Total Findings", str(risk.total_items), icon="🔎", tone="blue", insight=f"{risk.total_categories} categories")
    with cols[1]:
        kpi_card("Risk Score", str(risk.score), icon="⚠️", tone="red" if risk.score > 70 else ("amber" if risk.score > 30 else "green"), unit="/100")
    with cols[2]:
        kpi_card("Compliance Score", str(risk.compliance_score), icon="✅", tone="green" if risk.compliance_score > 70 else "amber", unit="/100")
    with cols[3]:
        kpi_card("High Risk Items", str(risk.high_risk_items), icon="🚨", tone="red" if risk.high_risk_items > 0 else "green")
    with cols[4]:
        kpi_card("Data Exposure", str(risk.data_exposure_score), icon="🔓", tone="red" if risk.data_exposure_score > 60 else "amber", unit="/100")
    with cols[5]:
        kpi_card("Document Health", str(risk.document_health_score), icon="💓", tone="green" if risk.document_health_score > 70 else "amber", unit="/100")

    st.write("")

    col_gauge, col_severity, col_trend = st.columns([1, 1, 1.2])

    with col_gauge:
        st.markdown('<div class="pc-section-title" style="font-size:15px;">Risk Meter</div>', unsafe_allow_html=True)
        fig = go.Figure(
            go.Indicator(
                mode="gauge+number",
                value=risk.score,
                domain={"x": [0, 1], "y": [0, 1]},
                gauge={
                    "axis": {"range": [0, 100], "tickcolor": "#5b6478"},
                    "bar": {"color": risk.color},
                    "bgcolor": "rgba(0,0,0,0)",
                    "steps": [
                        {"range": [0, 30], "color": "rgba(52,211,153,0.18)"},
                        {"range": [30, 70], "color": "rgba(251,191,36,0.18)"},
                        {"range": [70, 100], "color": "rgba(248,113,113,0.18)"},
                    ],
                },
                number={"font": {"color": "#e9edf5"}},
            )
        )
        fig.update_layout(
            height=240, margin=dict(l=20, r=20, t=10, b=10),
            paper_bgcolor="rgba(0,0,0,0)", font={"color": "#e9edf5"},
        )
        st.plotly_chart(fig, use_container_width=True)

    with col_severity:
        st.markdown('<div class="pc-section-title" style="font-size:15px;">Severity Distribution</div>', unsafe_allow_html=True)
        sev = risk.severity_distribution
        sev_df = pd.DataFrame({"Severity": list(sev.keys()), "Count": list(sev.values())})
        fig_sev = px.pie(
            sev_df, names="Severity", values="Count", hole=0.6, height=240,
            color="Severity",
            color_discrete_map={"High": "#f87171", "Medium": "#fbbf24", "Low": "#34d399"},
        )
        fig_sev.update_layout(
            margin=dict(l=10, r=10, t=10, b=10), paper_bgcolor="rgba(0,0,0,0)",
            font={"color": "#e9edf5"}, showlegend=True, legend={"orientation": "h", "y": -0.15},
        )
        st.plotly_chart(fig_sev, use_container_width=True)

    with col_trend:
        st.markdown('<div class="pc-section-title" style="font-size:15px;">Risk Trend (Session)</div>', unsafe_allow_html=True)
        hist_df = pd.DataFrame(st.session_state["history"])
        fig_trend = px.line(hist_df, x="timestamp", y="risk_score", markers=True, height=240)
        fig_trend.update_traces(line_color="#6c8cff", marker=dict(size=7, color="#a78bfa"))
        fig_trend.update_layout(
            margin=dict(l=10, r=10, t=10, b=10), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font={"color": "#e9edf5"}, xaxis={"showgrid": False}, yaxis={"gridcolor": "rgba(255,255,255,0.06)", "range": [0, 100]},
        )
        st.plotly_chart(fig_trend, use_container_width=True)

    st.write("")
    col_charts, col_reason = st.columns([1.3, 1])

    with col_charts:
        section_header("Detection Summary", "Volume and category breakdown of everything found.")
        if findings:
            df = pd.DataFrame([{"Type": f.data_type, "Count": f.count, "Category": f.category} for f in findings])
            fig_bar = px.bar(df, x="Type", y="Count", color="Category", height=300)
            fig_bar.update_layout(
                margin=dict(l=10, r=10, t=10, b=10), xaxis_tickangle=-35,
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font={"color": "#e9edf5"}, legend={"orientation": "h", "y": -0.4},
                xaxis={"showgrid": False}, yaxis={"gridcolor": "rgba(255,255,255,0.06)"},
            )
            st.plotly_chart(fig_bar, use_container_width=True)
        else:
            st.info("No sensitive data detected in this document.")

    with col_reason:
        section_header("Explainable AI", "Why the risk score is what it is.")
        if risk.breakdown:
            for item in risk.breakdown[:6]:
                st.markdown(
                    f"""<div class="pc-cat-card">
                    <div class="pc-cat-card-top">
                        <span class="pc-cat-card-title">{item['type']}</span>
                        <span style="color:#6c8cff; font-weight:700;">+{item['contribution']} pts</span>
                    </div>
                    <div style="font-size:11.5px; color:#8b93a7;">{item['reasoning']}</div>
                    </div>""",
                    unsafe_allow_html=True,
                )
        else:
            st.caption("No risk contributions — clean document.")

    st.write("")
    section_header("Sensitive Data Categories", "Detailed breakdown by data type.")
    if findings:
        cols_per_row = 3
        rows_of_findings = [findings[i:i + cols_per_row] for i in range(0, len(findings), cols_per_row)]
        for row in rows_of_findings:
            row_cols = st.columns(cols_per_row)
            for col, f in zip(row_cols, row):
                risk_level = "High Risk" if f.risk_weight >= 35 else ("Medium Risk" if f.risk_weight >= 18 else "Low Risk")
                impact = "Severe" if f.risk_weight >= 50 else ("Moderate" if f.risk_weight >= 25 else "Limited")
                with col:
                    category_card(
                        title=f.data_type,
                        count=f.count,
                        risk_level=risk_level,
                        confidence=f"{f.confidence*100:.0f}%",
                        impact=impact,
                    )
    else:
        st.info("No sensitive data types were detected.")

    with st.expander("📋 View Full Findings Table"):
        st.dataframe(pd.DataFrame(findings_summary_table(findings)), use_container_width=True, hide_index=True)


# ---------------------------------------------------------------------------
# PAGE: Compliance Report (Command Center)
# ---------------------------------------------------------------------------

def page_compliance() -> None:
    hero_section(
        "Compliance Command Center",
        "Framework-Mapped Risk & Recommendations",
        "Real-time compliance posture across GDPR, DPDP, PCI-DSS, ISO 27001, SOC 2, and HIPAA.",
    )

    if st.session_state["findings"] is None:
        st.warning("Run a detection scan first (Upload Document page).")
        return

    findings = st.session_state["findings"]
    risk = st.session_state["risk_assessment"]
    observations = st.session_state["compliance_observations"]
    scorecards = st.session_state["framework_scorecards"]
    doc = st.session_state["current_document"]

    section_header("Framework Scorecards")
    row1 = st.columns(3)
    row2 = st.columns(3)
    for col, card in zip(row1 + row2, scorecards):
        with col:
            framework_card(card.short_name, card.icon, card.compliance_score, card.risk_level)

    st.write("")
    section_header("Recommendations by Framework")
    tabs = st.tabs([c.short_name for c in scorecards])
    for tab, card in zip(tabs, scorecards):
        with tab:
            m1, m2 = st.columns([1, 2])
            with m1:
                metric_card("Compliance Score", f"{card.compliance_score}/100")
                st.write("")
                metric_card("Findings Triggered", str(card.findings_count))
            with m2:
                st.markdown('<div class="pc-kpi-label">Recommendations</div>', unsafe_allow_html=True)
                for rec in card.recommendations:
                    st.markdown(f"✅ {rec}")
            related_obs = [o for o in observations if o.framework == card.framework]
            if related_obs:
                with st.expander("View detailed concerns & impact"):
                    for obs in related_obs:
                        st.markdown(f"**Triggered by:** {obs.triggered_by}")
                        st.markdown(f"**Concern:** {obs.concern}")
                        st.markdown(f"**Impact:** {obs.impact}")
                        st.markdown("---")

    st.write("")
    st.markdown("---")
    section_header("AI Executive Briefing", "Scannable, bullet-capped analysis — no long paragraphs.")

    if not gemini_service.is_configured():
        st.info("Gemini is not connected. Set GEMINI_API_KEY in your .env file to enable the AI executive briefing.")
    else:
        if st.button("✨ Generate AI Executive Briefing", type="primary"):
            context = _build_ai_context(doc, findings, risk, observations)
            with st.spinner("Generating executive briefing with Gemini..."):
                briefing = gemini_service.generate_executive_briefing(context)
            if briefing:
                st.session_state["ai_briefing"] = briefing
            else:
                st.error("Could not generate the briefing. Please try again.")

        briefing = st.session_state["ai_briefing"]
        if briefing:
            b1, b2, b3, b4 = st.columns(4)
            _briefing_card(b1, "🎯 Executive Summary", briefing.get("executive_summary", []), "blue")
            _briefing_card(b2, "⚠️ Key Risks", briefing.get("key_risks", []), "red")
            _briefing_card(b3, "📋 Compliance Impact", briefing.get("compliance_impact", []), "amber")
            _briefing_card(b4, "🚀 Immediate Actions", briefing.get("immediate_actions", []), "green")

            st.write("")
            biz_col, _ = st.columns([2, 1])
            with biz_col:
                _briefing_card(st, "💼 Business Impact", briefing.get("business_impact", []), "purple")

    st.write("")
    st.markdown("---")
    section_header("Export Report")
    col1, col2, col3 = st.columns(3)

    long_form_summary = _briefing_to_markdown(st.session_state.get("ai_briefing"))

    with col1:
        pdf_bytes = build_pdf_report(doc.filename, findings, risk, observations, long_form_summary)
        if st.download_button("📄 Download PDF Report", data=pdf_bytes, file_name="proteccio_report.pdf", mime="application/pdf", use_container_width=True):
            audit_service.log_event("REPORT_EXPORT", st.session_state["session_id"], {"format": "pdf"})

    with col2:
        json_str = build_json_report(doc.filename, findings, risk, observations)
        if st.download_button("🧾 Download JSON", data=json_str, file_name="proteccio_report.json", mime="application/json", use_container_width=True):
            audit_service.log_event("REPORT_EXPORT", st.session_state["session_id"], {"format": "json"})

    with col3:
        csv_str = build_csv_report(findings)
        if st.download_button("📊 Download CSV Findings", data=csv_str, file_name="proteccio_findings.csv", mime="text/csv", use_container_width=True):
            audit_service.log_event("REPORT_EXPORT", st.session_state["session_id"], {"format": "csv"})


def _briefing_card(container, title: str, bullets: list, tone: str) -> None:
    bullets_html = "".join(f"<li style='margin-bottom:6px;'>{b}</li>" for b in bullets) if bullets else "<li style='color:#5b6478;'>No items.</li>"
    container.markdown(
        f"""<div class="pc-glass" style="min-height:180px;">
        <div class="pc-kpi-label" style="color:{'#f87171' if tone=='red' else '#fbbf24' if tone=='amber' else '#34d399' if tone=='green' else '#a78bfa' if tone=='purple' else '#60a5fa'};">{title}</div>
        <ul style="margin-top:10px; padding-left:18px; font-size:12.5px; color:#e9edf5;">{bullets_html}</ul>
        </div>""",
        unsafe_allow_html=True,
    )


def _briefing_to_markdown(briefing: dict | None) -> str:
    if not briefing:
        return ""
    sections = [
        ("Executive Summary", "executive_summary"),
        ("Key Risks", "key_risks"),
        ("Compliance Impact", "compliance_impact"),
        ("Immediate Actions", "immediate_actions"),
        ("Business Impact", "business_impact"),
    ]
    lines = []
    for title, key in sections:
        lines.append(f"## {title}")
        for bullet in briefing.get(key, []):
            lines.append(f"- {bullet}")
        lines.append("")
    return "\n".join(lines)


def _build_ai_context(doc, findings, risk, observations) -> str:
    lines = [
        f"Document: {doc.filename}",
        f"Risk Score: {risk.score}/100 ({risk.classification})",
        f"High Risk Items: {risk.high_risk_items}",
        f"Data Exposure Score: {risk.data_exposure_score}/100",
        "",
        "Findings:",
    ]
    for f in findings:
        lines.append(f"- {f.data_type} ({f.category}): {f.count} instance(s), confidence {f.confidence*100:.0f}%")
    lines.append("")
    lines.append("Compliance frameworks triggered: " + ", ".join(sorted({o.framework for o in observations})))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# PAGE: Redaction Center (Data Protection Center)
# ---------------------------------------------------------------------------

def page_redaction() -> None:
    hero_section(
        "Data Protection Center",
        "Redaction & Sanitization",
        "Preview, mask, and export a sanitized version of this document before sharing.",
    )

    if st.session_state["findings"] is None:
        st.warning("Run a detection scan first (Upload Document page).")
        return

    findings = st.session_state["findings"]
    doc = st.session_state["current_document"]
    risk = st.session_state["risk_assessment"]

    if not findings:
        st.info("No sensitive data found — nothing to redact.")
        return

    redaction_rows = build_redaction_map(findings)

    c1, c2, c3 = st.columns(3)
    with c1:
        kpi_card("Items to Redact", str(len(redaction_rows)), icon="🕶️", tone="amber")
    with c2:
        kpi_card("Current Risk Score", str(risk.score), icon="⚠️", tone="red", unit="/100")
    with c3:
        estimated_reduction = min(risk.score, int(risk.score * 0.85))
        kpi_card("Est. Risk After Redaction", str(risk.score - estimated_reduction), icon="🛡️", tone="green", unit="/100", insight=f"-{estimated_reduction} pts estimated")

    st.write("")
    section_header("Masked Value Preview", "Original values are never written to disk in this preview.")
    df = pd.DataFrame(redaction_rows).rename(columns={"data_type": "Data Type", "original": "Original", "masked": "Masked"})
    st.dataframe(df, use_container_width=True, hide_index=True)

    st.write("")
    if st.button("🕶️ Generate Sanitized Document", type="primary"):
        sanitized = redact_text(doc.text_content, findings)
        st.session_state["sanitized_text"] = sanitized
        audit_service.log_event(
            "REDACTION", st.session_state["session_id"], {"filename": doc.filename, "items_masked": len(redaction_rows)}
        )

    if st.session_state.get("sanitized_text"):
        st.success("Sanitized document generated.")
        section_header("Before / After Comparison")
        col_before, col_after = st.columns(2)
        with col_before:
            st.markdown('<div class="pc-kpi-label" style="color:#f87171;">🔓 Original (Unprotected)</div>', unsafe_allow_html=True)
            st.text_area("Original", doc.text_content[:2500], height=280, label_visibility="collapsed", key="orig_preview")
        with col_after:
            st.markdown('<div class="pc-kpi-label" style="color:#34d399;">🔒 Sanitized (Protected)</div>', unsafe_allow_html=True)
            st.text_area("Sanitized", st.session_state["sanitized_text"][:2500], height=280, label_visibility="collapsed", key="sanitized_preview")

        st.download_button(
            "⬇️ Download Sanitized Document",
            data=st.session_state["sanitized_text"],
            file_name=f"sanitized_{doc.filename}.txt",
            mime="text/plain",
            type="primary",
        )


# ---------------------------------------------------------------------------
# PAGE: Document Chat
# ---------------------------------------------------------------------------

def page_chat() -> None:
    hero_section(
        "Document Intelligence Chat",
        "Ask Anything About This Document",
        "Retrieval-augmented Q&A grounded in the document's actual content — with sources and confidence.",
    )

    doc = st.session_state["current_document"]
    if doc is None:
        st.warning("Upload a document first.")
        return

    if not gemini_service.is_configured():
        st.info("Gemini is not connected. Set GEMINI_API_KEY in your .env file to enable document chat.")

    if st.session_state["rag_index"] is None:
        with st.spinner("Indexing document for retrieval..."):
            st.session_state["rag_index"] = build_index(doc.text_content)

    mode = st.session_state["rag_index"].mode
    mode_label = "Semantic (FAISS)" if mode == "embedding" else "Keyword Fallback"
    st.caption(f"🔗 Retrieval mode: **{mode_label}** · {len(st.session_state['rag_index'].chunks)} indexed chunks")

    for turn in st.session_state["chat_history"]:
        if turn["role"] == "user":
            chat_bubble("user", turn["content"])
        else:
            meta = ""
            if "confidence" in turn:
                conf_pct = int(turn["confidence"] * 100)
                meta = f"🎯 Confidence: {conf_pct}% · {turn.get('reasoning', '')}"
            chat_bubble("assistant", turn["content"], meta=meta)
            if turn.get("sources"):
                with st.expander(f"📚 View {len(turn['sources'])} retrieved source(s)"):
                    for i, src in enumerate(turn["sources"], 1):
                        st.markdown(f"**Chunk {i}** · confidence {int(src['confidence']*100)}%")
                        st.caption(src["preview"])

    st.markdown("###### Suggested questions")
    suggestions = [
        "What sensitive data exists?",
        "Summarize this document",
        "What compliance risks exist?",
        "What should be redacted?",
    ]
    cols = st.columns(len(suggestions))
    clicked_suggestion = None
    for col, suggestion in zip(cols, suggestions):
        if col.button(suggestion, use_container_width=True):
            clicked_suggestion = suggestion

    question = st.chat_input("Ask a question about this document...")
    final_question = clicked_suggestion or question

    if final_question:
        st.session_state["chat_history"].append({"role": "user", "content": final_question})
        with st.spinner("Retrieving context and generating answer..."):
            result = answer_question(st.session_state["rag_index"], final_question, st.session_state["chat_history"])
        st.session_state["chat_history"].append(
            {
                "role": "assistant",
                "content": result["answer"],
                "confidence": result["confidence"],
                "reasoning": result["reasoning"],
                "sources": result["sources"],
            }
        )

        audit_service.log_event(
            "CHAT_QUERY", st.session_state["session_id"], {"filename": doc.filename, "question": final_question}
        )
        st.rerun()


# ---------------------------------------------------------------------------
# PAGE: Audit Logs (Security Activity Timeline)
# ---------------------------------------------------------------------------

EVENT_ICON_TONE = {
    "UPLOAD": ("📤", "blue"),
    "DETECTION": ("🔎", "purple"),
    "RISK_ASSESSMENT": ("⚠️", "amber"),
    "CHAT_QUERY": ("💬", "blue"),
    "REDACTION": ("🕶️", "green"),
    "REPORT_EXPORT": ("📄", "green"),
    "UNKNOWN": ("❔", "amber"),
}


def page_audit_logs() -> None:
    hero_section(
        "Security Activity Timeline",
        "Full Audit Trail",
        "Every upload, scan, chat query, redaction, and export — logged and traceable.",
    )

    logs = audit_service.read_audit_log()

    if not logs:
        st.info("No audit events recorded yet.")
        return

    event_types = sorted({log["event_type"] for log in logs})
    event_filter = st.multiselect("Filter by event type", event_types)
    filtered_logs = [log for log in logs if not event_filter or log["event_type"] in event_filter]

    c1, c2, c3 = st.columns(3)
    with c1:
        kpi_card("Total Events", str(len(logs)), icon="🧾", tone="blue")
    with c2:
        kpi_card("Documents Processed", str(len(st.session_state.get("history", []))), icon="📄", tone="purple")
    with c3:
        kpi_card("Chat Queries", str(sum(1 for l in logs if l["event_type"] == "CHAT_QUERY")), icon="💬", tone="green")

    st.write("")

    if st.session_state.get("history"):
        section_header("Risk Score Trend", "Across all documents scanned this session.")
        hist_df = pd.DataFrame(st.session_state["history"])
        fig = px.line(hist_df, x="timestamp", y="risk_score", markers=True, height=220)
        fig.update_traces(line_color="#6c8cff", marker=dict(size=7, color="#a78bfa"))
        fig.update_layout(
            margin=dict(l=10, r=10, t=10, b=10), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font={"color": "#e9edf5"}, xaxis={"showgrid": False}, yaxis={"gridcolor": "rgba(255,255,255,0.06)"},
        )
        st.plotly_chart(fig, use_container_width=True)

    st.write("")
    section_header("Activity Timeline")

    st.markdown('<div class="pc-timeline">', unsafe_allow_html=True)
    for log in filtered_logs[:60]:
        icon, tone = EVENT_ICON_TONE.get(log["event_type"], EVENT_ICON_TONE["UNKNOWN"])
        detail_str = ", ".join(f"{k}: {v}" for k, v in log.get("details", {}).items())
        timeline_item(
            icon=icon,
            tone=tone,
            title=log["event_type"].replace("_", " ").title(),
            meta=log["timestamp"],
            detail=detail_str,
        )
    st.markdown("</div>", unsafe_allow_html=True)

    st.write("")
    if st.button("🗑️ Clear Audit Log"):
        audit_service.clear_audit_log()
        st.rerun()


# ---------------------------------------------------------------------------
# PAGE: About Platform
# ---------------------------------------------------------------------------

def page_about() -> None:
    hero_section(
        "About the Platform",
        "Proteccio Data — AI Compliance Intelligence Platform",
        "An end-to-end sensitive data detection, risk scoring, compliance mapping, and document "
        "intelligence platform built on Google Gemini, FAISS, and Streamlit.",
    )

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        kpi_card("Detection Rules", "15+", icon="🔎", tone="blue")
    with c2:
        kpi_card("Compliance Frameworks", "6", icon="📋", tone="purple")
    with c3:
        kpi_card("Report Formats", "3", icon="📄", tone="green", insight="PDF · JSON · CSV")
    with c4:
        kpi_card("Pages", "7", icon="🧭", tone="amber")

    st.write("")
    section_header("Architecture", "How a document flows through the platform.")
    st.graphviz_chart(
        """
        digraph G {
            rankdir=LR;
            bgcolor="transparent";
            node [shape=box, style="rounded,filled", fillcolor="#161b28", fontcolor="#e9edf5", color="#2a3040", fontname="Helvetica"];
            edge [color="#5b6478", fontcolor="#8b93a7", fontname="Helvetica", fontsize=10];

            Upload [label="Upload\\n(PDF/TXT/CSV)"];
            Extract [label="Text Extraction"];
            Detect [label="Detection Engine\\n(Regex + Entropy)"];
            Risk [label="Risk Engine\\n(Weighted Scoring)"];
            Compliance [label="Compliance Engine\\n(Framework Mapping)"];
            Redact [label="Redaction Engine"];
            Chunk [label="Chunking"];
            Embed [label="Gemini Embeddings"];
            FAISS [label="FAISS Index"];
            Gemini [label="Gemini Generation"];
            Report [label="Report Export\\n(PDF/JSON/CSV)"];
            Audit [label="Audit Log"];

            Upload -> Extract -> Detect;
            Detect -> Risk -> Compliance;
            Detect -> Redact;
            Extract -> Chunk -> Embed -> FAISS;
            FAISS -> Gemini;
            Compliance -> Report;
            Risk -> Report;
            Gemini -> Report [style=dashed];
            Upload -> Audit [style=dotted];
            Detect -> Audit [style=dotted];
            Redact -> Audit [style=dotted];
        }
        """
    )

    st.write("")
    col_rag, col_stack = st.columns(2)

    with col_rag:
        section_header("RAG Pipeline")
        st.markdown(
            """
1. **Chunking** — ~800 character overlapping chunks
2. **Embeddings** — Gemini `text-embedding-004`
3. **Indexing** — FAISS `IndexFlatL2` similarity search
4. **Retrieval** — top-4 relevant chunks per query
5. **Generation** — Gemini answers grounded in retrieved context

Falls back to keyword-overlap retrieval if no API key is configured,
so Document Chat degrades gracefully rather than failing.
            """
        )

    with col_stack:
        section_header("Technology Stack")
        stack_items = [
            ("Frontend", "Streamlit + custom CSS design system"),
            ("AI / LLM", "Google Gemini 1.5 Flash"),
            ("Vector Search", "FAISS"),
            ("Document Processing", "PyPDF2, Pandas"),
            ("Visualization", "Plotly"),
            ("Reporting", "ReportLab (PDF)"),
        ]
        for label, val in stack_items:
            st.markdown(f"**{label}:** {val}")

    st.write("")
    section_header("AI Components")
    ai1, ai2, ai3 = st.columns(3)
    with ai1:
        st.markdown('<div class="pc-glass"><b>Document Intelligence</b><br/><span style="color:#8b93a7; font-size:12.5px;">AI-generated summary, category, and topic extraction with heuristic fallback.</span></div>', unsafe_allow_html=True)
    with ai2:
        st.markdown('<div class="pc-glass"><b>Executive Briefing</b><br/><span style="color:#8b93a7; font-size:12.5px;">Structured JSON output enforcing strict bullet caps for scannability.</span></div>', unsafe_allow_html=True)
    with ai3:
        st.markdown('<div class="pc-glass"><b>RAG Document Chat</b><br/><span style="color:#8b93a7; font-size:12.5px;">Grounded Q&A with source attribution and retrieval confidence.</span></div>', unsafe_allow_html=True)

    st.write("")
    st.caption(
        "This build is a demonstration/portfolio project and should not be treated as a "
        "substitute for legal compliance review."
    )


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

PAGE_ROUTER = {
    "Upload Document": page_upload,
    "Detection Dashboard": page_dashboard,
    "Compliance Report": page_compliance,
    "Redaction Center": page_redaction,
    "Document Chat": page_chat,
    "Audit Logs": page_audit_logs,
    "About Platform": page_about,
}


def main() -> None:
    selected_page = render_sidebar()
    # Allow in-page buttons (e.g. "View Detection Dashboard") to override nav
    page_to_render = st.session_state.pop("_nav_override", None) or selected_page
    PAGE_ROUTER.get(page_to_render, page_upload)()


if __name__ == "__main__":
    main()
