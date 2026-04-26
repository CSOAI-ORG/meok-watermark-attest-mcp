#!/usr/bin/env python3
"""
EU AI Act Watermark + Transparency Attest MCP Server
======================================================
By MEOK AI Labs | https://meok.ai

The MCP for the **2 November 2026 EU AI Act watermarking cliff** (Article 50).

CONTEXT:
  Following the Digital Omnibus delay (EU Parliament vote 569-45 on 23 Mar 2026),
  high-risk AI obligations slipped to Dec 2027 / Aug 2028. But Article 50
  transparency + watermarking obligations now bite on **2 November 2026** —
  the new nearest EU AI Act cliff.

WHO MUST COMPLY:
  - Any provider of an AI system that interacts with humans (chatbots) — Art 50(1)
  - Any provider/deployer of GPAI generating synthetic audio / image / video / text — Art 50(2-3)
  - Deployers of emotion-recognition + biometric-categorisation systems — Art 50(4)
  - Deployers generating deepfakes — Art 50(4)

PROBLEM SOLVED: most teams don't know which Art 50 obligations apply to them,
how to embed machine-readable marks (per draft Commission guidelines), or how
to prove they did. This MCP audits, generates disclosure text, validates marker
embedding, and emits a HMAC-signed compliance attestation per content type.

  💷 PRICE: Free 10/day. Pro £199/mo unlocks signed attestations + audit log.
            Enterprise £1,499/mo for content-pipeline integration.
            £499 one-off "Article 50 Readiness Pack" via Stripe.

Install: pip install meok-watermark-attest-mcp
Run:     python server.py
"""

import json
import hashlib
import re
from datetime import datetime, timedelta, timezone
from typing import Optional
from collections import defaultdict, deque
from mcp.server.fastmcp import FastMCP

import os as _os
import sys
import os

_MEOK_API_KEY = _os.environ.get("MEOK_API_KEY", "")

try:
    sys.path.insert(0, os.path.expanduser("~/clawd/meok-labs-engine/shared"))
    from auth_middleware import check_access as _shared_check_access
except ImportError:
    def _shared_check_access(api_key: str = ""):
        if _MEOK_API_KEY and api_key and api_key == _MEOK_API_KEY:
            return True, "OK", "pro"
        if _MEOK_API_KEY and api_key and api_key != _MEOK_API_KEY:
            return False, "Invalid API key.", "free"
        return True, "OK", "free"


try:
    from attestation import get_attestation_tool_response
    _ATTESTATION_LOCAL = True
except ImportError:
    _ATTESTATION_LOCAL = False

# V-06 FIX: SSRF allowlist on attestation API URL.
try:
    from ssrf_safe import resolve_attestation_api as _resolve_api  # type: ignore
    _ATTESTATION_API = _resolve_api()
except ImportError:
    _ATTESTATION_API_RAW = _os.environ.get("MEOK_ATTESTATION_API", "https://meok-attestation-api.vercel.app")
    _ALLOWED_API_HOSTS = {"meok-attestation-api.vercel.app", "meok-verify.vercel.app", "meok.ai", "csoai.org", "councilof.ai", "compliance.meok.ai"}
    import urllib.parse as _urllib_parse
    try:
        _api_parsed = _urllib_parse.urlparse(_ATTESTATION_API_RAW)
        _api_host = (_api_parsed.hostname or "").lower()
        _api_scheme = (_api_parsed.scheme or "").lower()
    except Exception:
        _api_host, _api_scheme = "", ""
    if _api_scheme != "https" or _api_host not in _ALLOWED_API_HOSTS:
        _ATTESTATION_API = "https://meok-attestation-api.vercel.app"
    else:
        _ATTESTATION_API = _ATTESTATION_API_RAW.rstrip("/")


def check_access(api_key: str = ""):
    return _shared_check_access(api_key)


STRIPE_199 = "https://buy.stripe.com/14A4gB3K4eUWgYR56o8k836"
STRIPE_1499 = "https://buy.stripe.com/4gM9AV80kaEG0ZT42k8k837"
STRIPE_499 = "https://buy.stripe.com/4gM7sN2G0bIKeQJfL28k833"
FREE_DAILY_LIMIT = 10
DEADLINE_UTC = "2026-11-02T00:00:00+00:00"


# ── Article 50 obligation matrix ─────────────────────────────────
ART_50_OBLIGATIONS = {
    "art_50_1_chatbot_disclosure": {
        "trigger": "AI system intended to interact with natural persons (chatbots / voice assistants)",
        "obligation": "Inform natural persons they are interacting with an AI system, unless obvious from context",
        "who": "providers",
        "exception": "AI authorised by law to detect/prevent/investigate criminal offences (subject to safeguards)",
    },
    "art_50_2_synthetic_content_marking": {
        "trigger": "GPAI providers generating synthetic audio / image / video / text content",
        "obligation": "Ensure outputs are MARKED in a machine-readable format and DETECTABLE as artificially generated/manipulated",
        "who": "GPAI providers",
        "exception": "Outputs that perform an assistive function for standard editing or do not substantially alter input data; AI for criminal-offence prevention/investigation",
        "technical_options": [
            "Cryptographic watermarking (e.g. SynthID, C2PA Content Credentials)",
            "Steganographic markers in pixel/wave domain",
            "Metadata fingerprints (EXIF / XMP / ID3 / JSON-LD)",
            "Provenance manifests per C2PA 2.0",
        ],
    },
    "art_50_3_emotion_biometric": {
        "trigger": "Deployer of emotion-recognition system OR biometric-categorisation system",
        "obligation": "Inform exposed natural persons of system operation; process personal data per GDPR + LED + Reg 2018/1725",
        "who": "deployers",
        "exception": "Detect/prevent/investigate criminal offences (with safeguards)",
    },
    "art_50_4_deepfake_disclosure": {
        "trigger": "Deployer generating or manipulating image/audio/video constituting a 'deep fake'",
        "obligation": "Disclose that content has been artificially generated or manipulated",
        "who": "deployers",
        "exception": "Use authorised by law for criminal offences; for evidently artistic / creative / satirical / fictional analogous works — disclose 'in an appropriate manner'",
    },
    "art_50_4_text_disclosure": {
        "trigger": "Deployer publishing AI-generated/manipulated text on matters of public interest",
        "obligation": "Disclose the text has been artificially generated/manipulated",
        "who": "deployers",
        "exception": "AI-generated content has undergone human review/editorial control + a person/entity holds editorial responsibility",
    },
}


# Detection regexes — quick scan for already-present disclosure language
DISCLOSURE_PATTERNS = [
    (r"\b(AI[-\s]?generated|generated by AI|machine[-\s]?generated|artificially (generated|created|produced))\b", "ai-generated-claim"),
    (r"\b(this (is|was) an? (AI|chatbot|virtual assistant))\b", "chatbot-disclosure"),
    (r"\b(C2PA|content credentials|content provenance)\b", "c2pa-marker"),
    (r"\b(SynthID|StableSig|tree-ring watermark)\b", "watermark-system"),
    (r"\b(deepfake|deep[-\s]?fake|synthetic media|manipulated content)\b", "deepfake-disclosure"),
]


# Per-tenant content audit log
_audit_log: dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
_daily_calls: dict[str, int] = defaultdict(int)


def _days_to_deadline() -> int:
    deadline = datetime.fromisoformat(DEADLINE_UTC)
    return max(0, (deadline - datetime.now(timezone.utc)).days)


mcp = FastMCP(
    "meok-watermark-attest",
    instructions=(
        "MEOK AI Labs Article 50 Watermark + Transparency Attestation MCP. The "
        "compliance MCP for the 2 Nov 2026 EU AI Act watermarking cliff. Classify "
        "which Art 50 obligations apply to your AI system, generate compliant "
        "disclosure text, validate marker presence in content, audit your content "
        "pipeline, and emit HMAC-signed compliance attestations. Built for the "
        "Digital Omnibus post-delay landscape — Art 50 was NOT delayed beyond Nov 2026."
    ),
)


@mcp.tool()
def get_deadline_status(api_key: str = "") -> str:
    """Return live status of the 2 Nov 2026 Article 50 deadline + which Article
    50 obligations apply to whom."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": STRIPE_199})
    return json.dumps({
        "deadline_utc": DEADLINE_UTC,
        "days_to_go": _days_to_deadline(),
        "regulatory_basis": "EU AI Act Article 50 (Regulation (EU) 2024/1689) — confirmed unchanged by Digital Omnibus delay",
        "obligations": ART_50_OBLIGATIONS,
        "key_message": (
            "The Digital Omnibus delayed high-risk Annex III to Dec 2027, but Article 50 "
            "(chatbot disclosure + watermarking + deepfake disclosure + emotion-recognition "
            "transparency) was only pushed by 3 months — to 2 Nov 2026. This is now the "
            "FIRST EU AI Act cliff every chatbot operator + GPAI provider + deepfake user hits."
        ),
        "upsell": f"Pro £199/mo: signed Article 50 readiness attestations — {STRIPE_199}" if tier == "free" else None,
    }, indent=2)


@mcp.tool()
def classify_obligations(
    is_chatbot: bool = False,
    is_gpai_provider: bool = False,
    generates_synthetic_audio: bool = False,
    generates_synthetic_image: bool = False,
    generates_synthetic_video: bool = False,
    generates_synthetic_text: bool = False,
    deploys_emotion_recognition: bool = False,
    deploys_biometric_categorisation: bool = False,
    generates_deepfakes: bool = False,
    publishes_ai_text_public_interest: bool = False,
    api_key: str = "",
) -> str:
    """Given system characteristics, return the specific Article 50 obligations
    that apply + the disclosure templates needed."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": STRIPE_199})

    triggered = []
    if is_chatbot:
        triggered.append("art_50_1_chatbot_disclosure")
    if is_gpai_provider and (generates_synthetic_audio or generates_synthetic_image or generates_synthetic_video or generates_synthetic_text):
        triggered.append("art_50_2_synthetic_content_marking")
    if deploys_emotion_recognition or deploys_biometric_categorisation:
        triggered.append("art_50_3_emotion_biometric")
    if generates_deepfakes:
        triggered.append("art_50_4_deepfake_disclosure")
    if publishes_ai_text_public_interest:
        triggered.append("art_50_4_text_disclosure")

    if not triggered:
        return json.dumps({
            "in_scope": False,
            "message": "No Article 50 obligations triggered by these characteristics. Re-check if you generate synthetic content, run a chatbot, deploy emotion/biometric AI, or publish AI-text on public-interest matters.",
            "deadline_utc": DEADLINE_UTC,
        })

    return json.dumps({
        "in_scope": True,
        "deadline_utc": DEADLINE_UTC,
        "days_to_go": _days_to_deadline(),
        "obligations_triggered": triggered,
        "details": {k: ART_50_OBLIGATIONS[k] for k in triggered},
        "next_step": "Call generate_disclosure_text() for each obligation OR audit_content_pipeline() to scan existing pipeline",
        "upsell": f"Pro £199/mo: signed readiness attestations + content-pipeline integration: {STRIPE_199}" if tier == "free" else None,
    }, indent=2)


@mcp.tool()
def generate_disclosure_text(
    obligation_key: str,
    surface_type: str = "ui",
    language: str = "en",
    api_key: str = "",
) -> str:
    """Generate compliant disclosure text for a specific Article 50 obligation.

    - obligation_key: one of the keys returned by classify_obligations
    - surface_type: ui | api | metadata | tts_audio | image_caption
    - language: en | de | fr | es | it
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": STRIPE_199})
    if obligation_key not in ART_50_OBLIGATIONS:
        return json.dumps({"error": f"unknown obligation_key: {obligation_key}", "valid": list(ART_50_OBLIGATIONS.keys())})

    templates = {
        "art_50_1_chatbot_disclosure": {
            "ui_en": "You're chatting with an AI. Anything I say should be checked against authoritative sources.",
            "ui_de": "Sie chatten mit einer KI. Bitte überprüfen Sie meine Antworten anhand verlässlicher Quellen.",
            "ui_fr": "Vous discutez avec une IA. Toute information que je fournis devrait être vérifiée auprès de sources autoritatives.",
            "ui_es": "Estás chateando con una IA. Toda información debe verificarse con fuentes autorizadas.",
            "ui_it": "Stai chattando con un'IA. Verifica ogni informazione presso fonti autorevoli.",
            "api_en": '{"ai_disclosure": "You are interacting with an AI assistant.", "human_in_loop": false}',
        },
        "art_50_2_synthetic_content_marking": {
            "metadata_en": '{"@context":"https://schema.org","@type":"DigitalDocument","disclaimer":"This content was generated by AI","provenance":{"@type":"ProvenanceRecord","standard":"C2PA-2.0","signed":true,"signer":"<your-org-key-id>"}}',
            "image_caption_en": "AI-generated image. Provenance: C2PA-2.0 manifest attached.",
            "tts_audio_en": "The following audio is AI-generated.",
        },
        "art_50_3_emotion_biometric": {
            "ui_en": "This system analyses cues such as facial expression / voice tone to estimate emotional state. Your data is processed under GDPR Article 9. You can withdraw consent at: <link>",
            "ui_de": "Dieses System analysiert Mimik / Stimmlage zur Einschätzung des emotionalen Zustands. Ihre Daten werden gemäß Art. 9 DSGVO verarbeitet. Einwilligung widerrufbar unter: <link>",
        },
        "art_50_4_deepfake_disclosure": {
            "ui_en": "🎬 This image / audio / video is AI-generated or AI-manipulated. It does not depict a real event.",
            "image_caption_en": "AI-generated. Not a real photograph.",
            "metadata_en": '{"@context":"https://schema.org","contentSource":"AI-generated","disclaimer":"This content does not depict a real event"}',
        },
        "art_50_4_text_disclosure": {
            "ui_en": "📝 This article was generated or substantially assisted by AI. Editorial oversight: <person + role>.",
        },
    }
    obligation_templates = templates.get(obligation_key, {})
    key = f"{surface_type}_{language}"
    text = obligation_templates.get(key)
    if not text:
        # Fallback to en
        fallback_key = f"{surface_type}_en"
        text = obligation_templates.get(fallback_key)
    if not text:
        return json.dumps({
            "error": f"no template available for {obligation_key} / {surface_type} / {language}",
            "available_combinations": list(obligation_templates.keys()),
            "upsell": f"Enterprise £1,499/mo: bespoke disclosure templates per language + jurisdiction: {STRIPE_1499}",
        })
    return json.dumps({
        "obligation_key": obligation_key,
        "surface_type": surface_type,
        "language": language,
        "disclosure_text": text,
        "where_to_render": {
            "ui": "Display before / at the start of every conversation. Persistent label in chat header.",
            "api": "Include in every API response payload at top level.",
            "metadata": "Embed in image EXIF, audio ID3, video MP4 metadata, document XMP, JSON-LD.",
            "tts_audio": "Spoken by TTS at start of audio.",
            "image_caption": "Visible caption overlay.",
        }.get(surface_type, "Render where the human encounters the AI output."),
    }, indent=2)


@mcp.tool()
def audit_content_pipeline(
    tenant_id: str,
    sample_text: str = "",
    pipeline_steps_csv: str = "",
    api_key: str = "",
) -> str:
    """Audit an existing content-generation pipeline for Article 50 compliance.
    Pass sample output text + comma-separated pipeline steps."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": STRIPE_199})

    today = datetime.now(timezone.utc).date().isoformat()
    _daily_calls[f"{tenant_id}:{today}"] += 1
    if tier == "free" and _daily_calls[f"{tenant_id}:{today}"] > FREE_DAILY_LIMIT:
        return json.dumps({"error": f"Free tier {FREE_DAILY_LIMIT} audits/day. Upgrade.", "upgrade_url": STRIPE_199})

    findings = []
    severity = "low"

    # Sample-text scan
    text_lc = (sample_text or "").lower()
    matched = []
    for pattern, name in DISCLOSURE_PATTERNS:
        if re.search(pattern, text_lc, re.IGNORECASE):
            matched.append(name)
    if not matched and sample_text:
        findings.append({
            "issue": "Sample output contains NO detectable disclosure / watermark marker",
            "severity": "HIGH",
            "fix": "Embed disclosure text via generate_disclosure_text(); add metadata marker per C2PA-2.0",
        })
        severity = "high"
    elif matched:
        findings.append({
            "issue": "Sample output contains detectable markers",
            "severity": "INFO",
            "matched_patterns": matched,
        })

    # Pipeline-step audit
    steps = [s.strip().lower() for s in pipeline_steps_csv.split(",") if s.strip()]
    expected_steps = {
        "marker_embedding": ["watermark", "c2pa", "synthid", "metadata", "marker"],
        "disclosure_render": ["disclosure", "label", "banner", "ui"],
        "audit_logging": ["log", "audit", "record"],
    }
    for label, keywords in expected_steps.items():
        if not any(kw in step for kw in keywords for step in steps):
            findings.append({
                "issue": f"Pipeline appears to MISSING step: {label}",
                "severity": "MEDIUM",
                "fix": f"Add explicit {label} step in your generation pipeline",
            })
            if severity == "low":
                severity = "medium"

    record = {
        "ts_utc": datetime.now(timezone.utc).isoformat(),
        "tenant_id": tenant_id,
        "severity": severity,
        "findings_count": len(findings),
        "sample_text_hash": hashlib.sha256((sample_text or "").encode()).hexdigest()[:16],
    }
    _audit_log[tenant_id].append(record)

    return json.dumps({
        "tenant_id": tenant_id,
        "audit_severity": severity,
        "deadline_utc": DEADLINE_UTC,
        "days_to_go": _days_to_deadline(),
        "findings": findings,
        "next_steps": [
            "If HIGH: embed disclosure text via generate_disclosure_text() in EVERY output path",
            "If MEDIUM: add the named pipeline step",
            "When green: call sign_watermark_attestation() for audit-evidence cert",
        ],
        "upsell": f"Pro £199/mo: signed audit attestations + monthly content-pipeline regression checks: {STRIPE_199}" if tier == "free" else None,
    }, indent=2)


@mcp.tool()
def sign_watermark_attestation(
    entity_name: str,
    audited_obligations_csv: str,
    pipeline_compliance_score: float,
    findings_csv: str = "",
    api_key: str = "",
    email: str = "",
) -> str:
    """Generate a HMAC-SHA256 signed attestation of Article 50 compliance for a
    given content pipeline. Pro/Enterprise required."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": STRIPE_199})
    if tier == "free":
        return json.dumps({
            "error": "Signed Article 50 attestations require Pro (£199/mo) or Enterprise tier.",
            "upgrade_url": STRIPE_199,
            "why_pro": "Hand the cert to your compliance counsel + customer procurement teams. Public verify URL = no backend chasing.",
        })
    findings = [f.strip() for f in findings_csv.split(",") if f.strip()] or [
        f"Pipeline compliance score: {pipeline_compliance_score}%",
        f"Audited obligations: {audited_obligations_csv}",
    ]
    payload = {
        "regulation": "EU AI Act Article 50 (Regulation (EU) 2024/1689) — Watermarking + Transparency",
        "entity": entity_name,
        "score": pipeline_compliance_score,
        "findings": findings,
        "tier": tier,
    }
    if _ATTESTATION_LOCAL:
        cert = get_attestation_tool_response(
            regulation=payload["regulation"], entity=entity_name,
            score=pipeline_compliance_score, findings=findings,
            articles_audited=[a.strip() for a in audited_obligations_csv.split(",") if a.strip()],
            tier=tier,
        )
    else:
        import urllib.request as _url
        try:
            req = _url.Request(
                f"{_ATTESTATION_API}/sign",
                data=json.dumps({"api_key": api_key, "email": email, **payload}).encode(),
                headers={"Content-Type": "application/json"},
            )
            with _url.urlopen(req, timeout=15) as resp:
                cert = json.loads(resp.read())
        except Exception as e:
            return json.dumps({"error": f"Attestation API unreachable: {e}"})
    return json.dumps(cert, indent=2)


def main():
    mcp.run()


if __name__ == "__main__":
    main()
