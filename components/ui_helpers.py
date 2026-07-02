"""
ui_helpers.py
--------------
Reusable Streamlit UI building blocks for the enterprise dashboard
redesign: CSS loader, KPI cards with trend/insight, risk badges,
compliance framework cards, progress bars, timeline items, and chat
bubbles with metadata (sources/confidence).

Kept framework-agnostic (pure HTML/CSS string builders) so app.py
stays focused on layout/orchestration rather than markup.
"""

from __future__ import annotations

import os

import streamlit as st

_ASSETS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets")

TONE_COLORS = {
    "blue": "#60a5fa",
    "green": "#34d399",
    "amber": "#fbbf24",
    "red": "#f87171",
    "purple": "#a78bfa",
}


def load_css() -> None:
    """Inject the custom stylesheet once per session."""
    css_path = os.path.join(_ASSETS_DIR, "style.css")
    with open(css_path, "r", encoding="utf-8") as f:
        css = f.read()
    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)


def render_brand_header() -> None:
    """Sidebar logo + product name block."""
    st.markdown(
        """
        <div class="pc-sidebar-brand">
            <div class="pc-logo">🛡️</div>
            <div class="pc-brand-text">
                <h2>Proteccio Data</h2>
                <span>COMPLIANCE INTELLIGENCE</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def hero_section(eyebrow: str, title: str, subtitle: str) -> None:
    st.markdown(
        f"""
        <div class="pc-hero">
            <div class="pc-hero-eyebrow">{eyebrow}</div>
            <div class="pc-hero-title">{title}</div>
            <div class="pc-hero-sub">{subtitle}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def section_header(title: str, subtitle: str = "") -> None:
    st.markdown(f'<div class="pc-section-title">{title}</div>', unsafe_allow_html=True)
    if subtitle:
        st.markdown(f'<div class="pc-section-sub">{subtitle}</div>', unsafe_allow_html=True)


def divider_label(label: str) -> None:
    st.markdown(f'<div class="pc-divider-label">{label}</div>', unsafe_allow_html=True)


def kpi_card(
    label: str,
    value: str,
    icon: str = "📊",
    tone: str = "blue",
    trend: str | None = None,
    trend_direction: str = "flat",  # up | down | flat
    insight: str | None = None,
    unit: str = "",
) -> None:
    """Render a single KPI card with icon, value, trend arrow, and mini insight."""
    trend_html = ""
    if trend:
        arrow = {"up": "▲", "down": "▼", "flat": "●"}.get(trend_direction, "●")
        trend_html = f'<div class="pc-kpi-trend {trend_direction}">{arrow} {trend}</div>'

    insight_html = f'<div class="pc-kpi-insight">{insight}</div>' if insight else ""
    unit_html = f'<span class="pc-kpi-unit">{unit}</span>' if unit else ""

    html = f"""<div class="pc-kpi">
<div class="pc-kpi-top">
<div class="pc-kpi-label">{label}</div>
<div class="pc-kpi-icon pc-icon-{tone}">{icon}</div>
</div>
<div class="pc-kpi-value">{value}{unit_html}</div>
{trend_html}
{insight_html}
</div>"""

    st.markdown(html, unsafe_allow_html=True)

def metric_card(label: str, value: str, sub: str = "") -> None:
    """Simple stat card (kept for lightweight contexts like document metadata)."""
    st.markdown(
        f"""
        <div class="pc-glass">
            <div class="pc-kpi-label">{label}</div>
            <div class="pc-kpi-value" style="font-size:22px;">{value}</div>
            <div class="pc-kpi-insight">{sub}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def risk_badge(classification: str) -> str:
    """Return an HTML badge span for a given risk classification string."""
    css_class = {
        "Low Risk": "pc-badge-low",
        "Medium Risk": "pc-badge-medium",
        "High Risk": "pc-badge-high",
    }.get(classification, "pc-badge-medium")
    return f'<span class="pc-badge {css_class}">{classification}</span>'


def status_block(title: str, rows: list[tuple[str, str, str]]) -> None:
    """
    Render a sidebar system-status block.
    rows: list of (label, status_text, tone) where tone is green/amber/red.
    """
    rows_html = ""
    for label, status_text, tone in rows:
        rows_html += f"""
        <div class="pc-status-row">
            <span class="pc-status-name"><span class="pc-dot pc-dot-{tone}"></span>{label}</span>
            <span class="pc-status-value {tone}">{status_text}</span>
        </div>
        """
    st.markdown(
        f"""
        <div class="pc-status-block">
            <div class="pc-status-title">{title}</div>
            {rows_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


def category_card(title: str, count: int, risk_level: str, confidence: str, impact: str, icon: str = "🔎") -> None:
    tone = {"Low Risk": "green", "Medium Risk": "amber", "High Risk": "red"}.get(risk_level, "blue")
    st.markdown(
        f"""
        <div class="pc-cat-card">
            <div class="pc-cat-card-top">
                <div class="pc-cat-card-title">{icon} {title}</div>
                <div class="pc-cat-card-count">{count}</div>
            </div>
            {risk_badge(risk_level)}
            <div class="pc-cat-meta">
                <span><b>Confidence</b> {confidence}</span>
                <span><b>Impact</b> {impact}</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def progress_bar(pct: int, color: str = "#6c8cff") -> None:
    pct = max(0, min(100, pct))
    st.markdown(
        f"""
        <div class="pc-progress-track">
            <div class="pc-progress-fill" style="width:{pct}%; background:{color};"></div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def framework_card(name: str, icon: str, score: int, risk_level: str) -> None:
    tone_color = {"Low Risk": "#34d399", "Medium Risk": "#fbbf24", "High Risk": "#f87171"}.get(risk_level, "#60a5fa")
    st.markdown(
        f"""
        <div class="pc-framework-card">
            <div class="pc-framework-icon">{icon}</div>
            <div class="pc-framework-name">{name}</div>
            <div class="pc-framework-score" style="color:{tone_color};">{score}%</div>
            {risk_badge(risk_level)}
        </div>
        """,
        unsafe_allow_html=True,
    )
    progress_bar(score, tone_color)


def timeline_item(icon: str, tone: str, title: str, meta: str, detail: str = "") -> None:
    color = TONE_COLORS.get(tone, "#60a5fa")
    detail_html = f'<div class="pc-timeline-detail">{detail}</div>' if detail else ""
    st.markdown(
        f"""
        <div class="pc-timeline-item">
            <div class="pc-timeline-dot" style="background:{color}22; color:{color};">{icon}</div>
            <div class="pc-timeline-content">
                <div class="pc-timeline-title">{title}</div>
                <div class="pc-timeline-meta">{meta}</div>
                {detail_html}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def chat_bubble(role: str, content: str, meta: str = "") -> None:
    css_class = "pc-chat-user" if role == "user" else "pc-chat-assistant"
    meta_html = f'<div class="pc-chat-meta">{meta}</div>' if meta else ""
    st.markdown(f'<div class="{css_class}">{content}{meta_html}</div>', unsafe_allow_html=True)


def pill(text: str) -> str:
    return f'<span class="pc-pill">{text}</span>'
