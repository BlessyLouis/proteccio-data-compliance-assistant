"""
risk_engine.py
--------------
Weighted risk scoring engine. Converts a list of detection Findings
into a single 0-100 risk score and a human-readable classification,
plus a plain-language breakdown ("risk reasoning") of how the score
was derived — used to build the Explainable AI section.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from services.detection_service import Finding

# Diminishing-returns cap: a data type with many repeated matches
# shouldn't linearly blow up the score (e.g. 500 emails != 500x risk).
MAX_MULTIPLIER_PER_TYPE = 3


@dataclass
class RiskAssessment:
    score: int
    classification: str  # Low / Medium / High
    color: str
    breakdown: list = field(default_factory=list)  # list of dicts: type, contribution, reasoning
    total_items: int = 0
    total_categories: int = 0
    compliance_score: int = 0
    high_risk_items: int = 0
    data_exposure_score: int = 0
    document_health_score: int = 0
    severity_distribution: dict = field(default_factory=dict)  # {"High": n, "Medium": n, "Low": n}


def classify_score(score: int) -> tuple[str, str]:
    if score <= 30:
        return "Low Risk", "#34d399"
    elif score <= 70:
        return "Medium Risk", "#fbbf24"
    else:
        return "High Risk", "#f87171"


# A finding type counts as "high severity" for the High Risk Items KPI
# and severity distribution if its base risk weight crosses this bar
# (credentials, financial data, national IDs land here; generic PII does not).
HIGH_SEVERITY_WEIGHT_THRESHOLD = 35


def compute_risk(findings: list[Finding]) -> RiskAssessment:
    """
    Compute an aggregate 0-100 risk score from findings, plus derived
    executive KPIs: high-risk item count, data exposure score, document
    health score, and a severity distribution for charting.

    Methodology:
    1. For each finding type, contribution = risk_weight * confidence
       * min(count, MAX_MULTIPLIER_PER_TYPE) — capped so volume alone
       doesn't dominate the score.
    2. Contributions are summed then normalized against a reference
       ceiling so the score fits cleanly into 0-100.
    3. Classified into Low / Medium / High bands.
    4. Data Exposure Score reflects how much sensitive *volume* is
       out in the open (weighted by category severity), independent
       of the concentration-capped risk score.
    5. Document Health Score is a simple inverse of risk, penalized
       further for high-severity categories (credentials, financial).
    """
    if not findings:
        return RiskAssessment(
            score=0,
            classification="Low Risk",
            color="#34d399",
            breakdown=[],
            total_items=0,
            total_categories=0,
            compliance_score=100,
            high_risk_items=0,
            data_exposure_score=0,
            document_health_score=100,
            severity_distribution={"High": 0, "Medium": 0, "Low": 0},
        )

    breakdown = []
    raw_total = 0.0
    high_risk_items = 0
    severity_distribution = {"High": 0, "Medium": 0, "Low": 0}
    exposure_raw = 0.0

    for f in findings:
        multiplier = min(f.count, MAX_MULTIPLIER_PER_TYPE)
        contribution = f.risk_weight * f.confidence * multiplier
        raw_total += contribution

        # Exposure score uses *uncapped* count so a document with many
        # leaked emails still shows high exposure even if risk-score
        # concentration capping limits its contribution there.
        exposure_raw += f.risk_weight * f.confidence * min(f.count, 10) * 0.6

        if f.risk_weight >= HIGH_SEVERITY_WEIGHT_THRESHOLD:
            high_risk_items += f.count
            severity_distribution["High"] += f.count
        elif f.risk_weight >= 18:
            severity_distribution["Medium"] += f.count
        else:
            severity_distribution["Low"] += f.count

        breakdown.append(
            {
                "type": f.data_type,
                "category": f.category,
                "count": f.count,
                "contribution": round(contribution, 1),
                "reasoning": (
                    f"{f.count} instance(s) of '{f.data_type}' detected "
                    f"(confidence {f.confidence * 100:.0f}%, base weight {f.risk_weight}). "
                    f"Capped multiplier applied: {multiplier}x."
                ),
            }
        )

    # Normalize: reference ceiling chosen so that a document with several
    # high-severity categories (credentials + financial + PII) reaches
    # ~100 without a single finding type dominating disproportionately.
    reference_ceiling = 260.0
    score = int(min(100, round((raw_total / reference_ceiling) * 100)))
    data_exposure_score = int(min(100, round((exposure_raw / 300.0) * 100)))

    classification, color = classify_score(score)

    total_items = sum(f.count for f in findings)
    total_categories = len({f.category for f in findings})
    compliance_score = max(0, 100 - score)

    # Document health penalizes presence of high-severity categories
    # more steeply than raw score alone would.
    health_penalty = min(40, high_risk_items * 4)
    document_health_score = max(0, min(100, 100 - int(round(score * 0.7)) - (health_penalty // 2)))

    # Sort breakdown by contribution, descending, for readability
    breakdown.sort(key=lambda x: x["contribution"], reverse=True)

    return RiskAssessment(
        score=score,
        classification=classification,
        color=color,
        breakdown=breakdown,
        total_items=total_items,
        total_categories=total_categories,
        compliance_score=compliance_score,
        high_risk_items=high_risk_items,
        data_exposure_score=data_exposure_score,
        document_health_score=document_health_score,
        severity_distribution=severity_distribution,
    )
