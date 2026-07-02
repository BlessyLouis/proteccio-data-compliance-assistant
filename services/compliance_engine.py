"""
compliance_engine.py
---------------------
Maps detected data categories to relevant compliance framework
observations: GDPR, ISO 27001, SOC 2, PCI-DSS, HIPAA (general
reference), and the Indian DPDP Act.

This is a rules-based mapping (not a legal opinion) intended to
demonstrate compliance-awareness in the product. Each observation
includes: framework, concern, impact, and recommendation.
"""

from __future__ import annotations

from dataclasses import dataclass

from services.detection_service import Finding


@dataclass
class ComplianceObservation:
    framework: str
    concern: str
    impact: str
    recommendation: str
    triggered_by: str


# Category -> list of (framework, concern, impact, recommendation) templates
_CATEGORY_RULES: dict[str, list[tuple[str, str, str, str]]] = {
    "PII": [
        (
            "GDPR",
            "Personal data (names, contact details, national IDs) present without confirmed lawful basis.",
            "Potential fines up to 4% of global annual turnover or €20M, whichever is higher.",
            "Confirm a lawful basis for processing, apply data minimization, and encrypt PII at rest and in transit.",
        ),
        (
            "Indian DPDP Act",
            "Personal data of Indian data principals detected without evident consent trail.",
            "Regulatory penalties and mandated breach notification to the Data Protection Board.",
            "Implement consent management and a documented data retention policy per the DPDP Act.",
        ),
        (
            "ISO 27001",
            "Personal data identified outside of a controlled information classification scheme.",
            "Non-conformance in Annex A controls related to information classification (A.5.12).",
            "Classify and label documents containing PII; restrict access using role-based controls.",
        ),
    ],
    "Financial": [
        (
            "PCI-DSS",
            "Cardholder or bank account data present in an unencrypted document.",
            "Non-compliance can result in fines, increased transaction fees, or loss of card processing privileges.",
            "Tokenize or encrypt cardholder data; avoid storing full PAN in plaintext documents.",
        ),
        (
            "SOC 2",
            "Financial data present without evidence of access restriction (Confidentiality criterion).",
            "Audit finding against SOC 2 Confidentiality trust service criteria.",
            "Restrict document access to authorized personnel and enable audit logging on access.",
        ),
    ],
    "Credentials": [
        (
            "ISO 27001",
            "Hardcoded credentials, API keys, or tokens found in a document.",
            "High risk of unauthorized system access if the document is leaked or mishandled.",
            "Rotate exposed credentials immediately; move secrets to a secure vault (e.g. AWS Secrets Manager, HashiCorp Vault).",
        ),
        (
            "SOC 2",
            "Secrets present outside of an approved secrets management system.",
            "Violates SOC 2 Security criteria around logical access controls.",
            "Enforce secret-scanning in CI/CD and revoke/rotate any credentials found in shared documents.",
        ),
    ],
    "Confidential": [
        (
            "SOC 2",
            "Internal/confidential business information found in a broadly accessible document.",
            "Risk of competitive harm or breach of confidentiality obligations.",
            "Apply document watermarking/classification and restrict distribution to a need-to-know basis.",
        ),
        (
            "ISO 27001",
            "Sensitive business information lacking a classification label.",
            "Gap in information labelling control (A.5.12) and handling procedures (A.5.13).",
            "Introduce a formal information classification and handling policy.",
        ),
    ],
    "Internal": [
        (
            "ISO 27001",
            "Internal identifiers (e.g. employee IDs) present in a document with unclear distribution scope.",
            "Minor risk of internal enumeration or social engineering if leaked externally.",
            "Limit sharing of internal identifiers outside the organization's trust boundary.",
        ),
    ],
}

_HIPAA_KEYWORDS = ("patient", "diagnosis", "medical record", "health insurance", "treatment plan")

# All frameworks always shown in the command center, even with zero
# findings, so the grid stays consistent across every scan.
ALL_FRAMEWORKS = ["GDPR", "Indian DPDP Act", "PCI-DSS", "ISO 27001", "SOC 2", "HIPAA (general reference)"]

FRAMEWORK_ICONS = {
    "GDPR": "🇪🇺",
    "Indian DPDP Act": "🇮🇳",
    "PCI-DSS": "💳",
    "ISO 27001": "🔒",
    "SOC 2": "🛡️",
    "HIPAA (general reference)": "🏥",
}

FRAMEWORK_SHORT_NAMES = {
    "GDPR": "GDPR",
    "Indian DPDP Act": "DPDP Act",
    "PCI-DSS": "PCI-DSS",
    "ISO 27001": "ISO 27001",
    "SOC 2": "SOC 2",
    "HIPAA (general reference)": "HIPAA",
}


@dataclass
class FrameworkScorecard:
    framework: str
    short_name: str
    icon: str
    compliance_score: int  # 0-100, higher is better
    risk_level: str  # Low Risk / Medium Risk / High Risk
    findings_count: int
    recommendations: list


def generate_compliance_observations(findings: list[Finding], full_text: str = "") -> list[ComplianceObservation]:
    """
    Given detection findings (and optionally the raw text for keyword
    checks like HIPAA), return a de-duplicated list of compliance
    observations relevant to what was actually detected.
    """
    observations: list[ComplianceObservation] = []
    triggered_categories = {f.category for f in findings}

    for category in triggered_categories:
        rules = _CATEGORY_RULES.get(category, [])
        matching_finding = next((f.data_type for f in findings if f.category == category), category)
        for framework, concern, impact, recommendation in rules:
            observations.append(
                ComplianceObservation(
                    framework=framework,
                    concern=concern,
                    impact=impact,
                    recommendation=recommendation,
                    triggered_by=matching_finding,
                )
            )

    # HIPAA general reference — only surfaced if health-related terms appear
    lowered = full_text.lower()
    if any(keyword in lowered for keyword in _HIPAA_KEYWORDS):
        observations.append(
            ComplianceObservation(
                framework="HIPAA (general reference)",
                concern="Document contains language suggestive of protected health information (PHI).",
                impact="If applicable, mishandling PHI can trigger HIPAA breach notification obligations.",
                recommendation="Verify whether the document falls under HIPAA scope; if so, apply PHI-specific safeguards.",
                triggered_by="Health-related keywords",
            )
        )

    if not observations:
        observations.append(
            ComplianceObservation(
                framework="General",
                concern="No high-risk categories detected in this document.",
                impact="Minimal immediate compliance exposure based on automated scan.",
                recommendation="Continue periodic scanning as document content evolves.",
                triggered_by="N/A",
            )
        )

    return observations


def compute_framework_scorecards(observations: list[ComplianceObservation]) -> list[FrameworkScorecard]:
    """
    Roll observations up into a per-framework scorecard for the
    Compliance Command Center: a 0-100 score (100 = fully clean),
    a risk level band, a findings count, and up to 3 recommendations.

    Score model: each observation against a framework deducts points;
    frameworks with no triggered observations score 100 (clean).
    """
    scorecards = []
    for framework in ALL_FRAMEWORKS:
        matched = [o for o in observations if o.framework == framework]
        findings_count = len(matched)

        # Deduct 22 points per distinct observation, floor at 5.
        score = max(5, 100 - findings_count * 22) if findings_count else 100

        if score >= 80:
            risk_level = "Low Risk"
        elif score >= 50:
            risk_level = "Medium Risk"
        else:
            risk_level = "High Risk"

        recommendations = [o.recommendation for o in matched][:3]
        if not recommendations:
            recommendations = ["No action required based on current scan results."]

        scorecards.append(
            FrameworkScorecard(
                framework=framework,
                short_name=FRAMEWORK_SHORT_NAMES.get(framework, framework),
                icon=FRAMEWORK_ICONS.get(framework, "📄"),
                compliance_score=score,
                risk_level=risk_level,
                findings_count=findings_count,
                recommendations=recommendations,
            )
        )

    return scorecards
