"""
report_service.py
-------------------
Generates downloadable compliance reports in three formats:
- PDF   : professional report using reportlab (executive summary, risk
          score, findings table, compliance observations, recommendations)
- JSON  : full structured findings + risk + compliance data
- CSV   : flat findings table

Kept separate from risk/compliance/detection engines to follow
single-responsibility: this module only formats/exports, it doesn't
compute anything.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)

from services.detection_service import Finding, findings_summary_table
from services.risk_engine import RiskAssessment
from services.compliance_engine import ComplianceObservation


def build_pdf_report(
    filename: str,
    findings: list[Finding],
    risk: RiskAssessment,
    observations: list[ComplianceObservation],
    ai_summary: str = "",
) -> bytes:
    """Build a professional PDF compliance report and return it as bytes."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.6 * inch, bottomMargin=0.6 * inch)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle", parent=styles["Title"], textColor=colors.HexColor("#1a1a2e"), fontSize=22
    )
    heading_style = ParagraphStyle(
        "ReportHeading", parent=styles["Heading2"], textColor=colors.HexColor("#0f3460"), spaceBefore=14
    )
    body_style = ParagraphStyle("ReportBody", parent=styles["Normal"], fontSize=10, leading=14)

    story = []

    # --- Cover / header ---
    story.append(Paragraph("Proteccio Data", title_style))
    story.append(Paragraph("Sensitive Data Detection & Compliance Report", styles["Heading3"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"Document analyzed: <b>{filename}</b>", body_style))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", body_style))
    story.append(Spacer(1, 16))

    # --- Risk score ---
    story.append(Paragraph("Risk Assessment", heading_style))
    risk_table_data = [
        ["Risk Score", f"{risk.score} / 100"],
        ["Classification", risk.classification],
        ["Total Sensitive Items", str(risk.total_items)],
        ["Categories Detected", str(risk.total_categories)],
        ["Compliance Score", f"{risk.compliance_score} / 100"],
    ]
    risk_table = Table(risk_table_data, colWidths=[200, 250])
    risk_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e8eef7")),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#1a1a2e")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(risk_table)
    story.append(Spacer(1, 16))

    # --- Findings table ---
    story.append(Paragraph("Detection Findings", heading_style))
    if findings:
        summary = findings_summary_table(findings)
        table_data = [["Data Type", "Category", "Count", "Confidence", "Risk Weight"]]
        for row in summary:
            table_data.append(
                [row["Data Type"], row["Category"], str(row["Count"]), row["Confidence"], str(row["Risk Weight"])]
            )
        findings_table = Table(table_data, colWidths=[130, 90, 50, 70, 80])
        findings_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f3460")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f7fa")]),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story.append(findings_table)
    else:
        story.append(Paragraph("No sensitive data detected.", body_style))

    story.append(Spacer(1, 16))

    # --- Compliance observations ---
    story.append(Paragraph("Compliance Observations", heading_style))
    for obs in observations:
        story.append(Paragraph(f"<b>{obs.framework}</b> — triggered by: {obs.triggered_by}", body_style))
        story.append(Paragraph(f"<i>Concern:</i> {obs.concern}", body_style))
        story.append(Paragraph(f"<i>Impact:</i> {obs.impact}", body_style))
        story.append(Paragraph(f"<i>Recommendation:</i> {obs.recommendation}", body_style))
        story.append(Spacer(1, 8))

    # --- AI executive summary ---
    if ai_summary:
        story.append(PageBreak())
        story.append(Paragraph("AI-Generated Executive Analysis", heading_style))
        for block in ai_summary.split("\n"):
            block = block.strip()
            if not block:
                continue
            if block.startswith("##"):
                story.append(Paragraph(block.replace("#", "").strip(), styles["Heading3"]))
            else:
                story.append(Paragraph(block, body_style))

    doc.build(story)
    buffer.seek(0)
    return buffer.read()


def build_json_report(
    filename: str,
    findings: list[Finding],
    risk: RiskAssessment,
    observations: list[ComplianceObservation],
) -> str:
    """Return a full structured JSON report as a string."""
    payload = {
        "document": filename,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "risk_assessment": {
            "score": risk.score,
            "classification": risk.classification,
            "total_items": risk.total_items,
            "total_categories": risk.total_categories,
            "compliance_score": risk.compliance_score,
            "breakdown": risk.breakdown,
        },
        "findings": [
            {
                "data_type": f.data_type,
                "category": f.category,
                "count": f.count,
                "confidence": f.confidence,
                "risk_weight": f.risk_weight,
                "matches": f.matches,
            }
            for f in findings
        ],
        "compliance_observations": [
            {
                "framework": o.framework,
                "concern": o.concern,
                "impact": o.impact,
                "recommendation": o.recommendation,
                "triggered_by": o.triggered_by,
            }
            for o in observations
        ],
    }
    return json.dumps(payload, indent=2)


def build_csv_report(findings: list[Finding]) -> str:
    """Return a flat CSV of findings (one row per data type)."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Data Type", "Category", "Count", "Confidence", "Risk Weight", "Sample Matches"])
    for f in findings:
        sample = "; ".join(f.matches[:3])
        writer.writerow([f.data_type, f.category, f.count, f"{f.confidence:.2f}", f.risk_weight, sample])
    return output.getvalue()
