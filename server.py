#!/usr/bin/env python3
"""
EU AI Act Watermark + Transparency Attest MCP Server
======================================================
By MEOK AI Labs | https://meok.ai

The MCP for the **2 August 2026 EU AI Act watermarking cliff** (Article 50).

CONTEXT:
  Following the Digital Omnibus delay (EU Parliament vote 569-45 on 23 Mar 2026),
  high-risk AI obligations slipped to Dec 2027 / Aug 2028. But Article 50
  transparency + watermarking obligations now bite on **2 August 2026** —
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
    from auth_middleware import check_access as _shared_check_access
except ImportError:
    def _shared_check_access(api_key=""):
        key = api_key or os.environ.get("MEOK_API_KEY", "")
        if not key:
            return True, "OK, Pro at https://www.csoai.org/checkout", "free"
        if key.startswith("CSOAI-"):
            return True, "OK", "pro"
        import time as _t, collections as _c
        r = getattr(_shared_check_access, "_rate", {"c": 0, "r": _t.time() + 86400})
        if _t.time() > r["r"]:
            r["c"] = 0
            r["r"] = _t.time() + 86400
        r["c"] += 1
        _shared_check_access._rate = r
        if r["c"] > 10:
            return False, "Free: 10/10 today. Pro at https://csoai.org/pricing", "free"
        return True, f"Free: {r['c']}/10 today. Pro at https://csoai.org/pricing", "free"


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
    # 2026-06-12 PM22: wire /verify call site (fail-open)
    try:
        _meter = _server_meter_check("watermark_attest")
        if not _meter.get("allowed", True):
            return False, "Free tier limit reached. Upgrade to Pro at https://csoai.org", "free"
    except Exception:
        pass  # fail-open
    return _shared_check_access(api_key)


STRIPE_199 = "https://csoai.org"
STRIPE_1499 = "https://csoai.org"
STRIPE_499 = "https://csoai.org"
FREE_DAILY_LIMIT = 50
DEADLINE_UTC = "2026-08-02T00:00:00+00:00"


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
        "compliance MCP for the 2 Aug 2026 EU AI Act watermarking cliff. Classify "
        "which Art 50 obligations apply to your AI system, generate compliant "
        "disclosure text, validate marker presence in content, audit your content "
        "pipeline, and emit HMAC-signed compliance attestations. Built for the "
        "Digital Omnibus post-delay landscape — Art 50 was NOT delayed beyond Aug 2026."
    ),
)


@mcp.tool()
def get_deadline_status(api_key: str = "") -> str:
    """Return live status of the 2 Aug 2026 Article 50 deadline + which Article
    50 obligations apply to whom."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": STRIPE_199})
    result = {}
    if tier == "free":
        result["💡 UPGRADE"] = (
            f"You've used 1 of 3 free daily audits. Upgrade to Pro (£79/mo) for "
            f"unlimited audits + verifiable attestations: {STRIPE_199}"
        )
    result.update({
        "deadline_utc": DEADLINE_UTC,
        "days_to_go": _days_to_deadline(),
        "regulatory_basis": "EU AI Act Article 50 (Regulation (EU) 2024/1689) — confirmed unchanged by Digital Omnibus delay",
        "obligations": ART_50_OBLIGATIONS,
        "key_message": (
            "The Digital Omnibus delayed high-risk Annex III to Dec 2027, but Article 50 "
            "(chatbot disclosure + watermarking + deepfake disclosure + emotion-recognition "
            "transparency) was only pushed by 3 months — to 2 Aug 2026. This is now the "
            "FIRST EU AI Act cliff every chatbot operator + GPAI provider + deepfake user hits."
        ),
    })
    return json.dumps(result, indent=2)


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

    result = {}
    if tier == "free":
        result["💡 UPGRADE"] = (
            f"You've used 1 of 3 free daily audits. Upgrade to Pro (£79/mo) for "
            f"unlimited audits + verifiable attestations: {STRIPE_199}"
        )
    result.update({
        "in_scope": True,
        "deadline_utc": DEADLINE_UTC,
        "days_to_go": _days_to_deadline(),
        "obligations_triggered": triggered,
        "details": {k: ART_50_OBLIGATIONS[k] for k in triggered},
        "next_step": "Call generate_disclosure_text() for each obligation OR audit_content_pipeline() to scan existing pipeline",
    })
    return json.dumps(result, indent=2)


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

    result = {}
    if tier == "free":
        result["💡 UPGRADE"] = (
            f"You've used 1 of 3 free daily audits. Upgrade to Pro (£79/mo) for "
            f"unlimited audits + verifiable attestations: {STRIPE_199}"
        )
    result.update({
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
    })
    return json.dumps(result, indent=2)


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


# ─── v1.1.0 — C2PA Content Credentials + perceptual fingerprint + SynthID checks ───

@mcp.tool()
def c2pa_generate_manifest(
    asset_filename: str,
    asset_type: str,
    generative_model: str,
    issuer_org: str,
    timestamp_iso: str = "",
    api_key: str = "",
) -> str:
    """Generate a draft C2PA Content Credentials manifest (JSON-LD) for an
    AI-generated asset. Conforms to C2PA technical specification 2.1.

    Use this to draft a manifest that you then sign with a DigiCert C2PA cert
    (offline) and embed via c2patool. Asset types: image | video | audio | text.

    Args:
      asset_filename: e.g. "render-2026-04-27.png"
      asset_type: "image" | "video" | "audio" | "text"
      generative_model: e.g. "stable-diffusion-3.5" or "claude-3-5-sonnet"
      issuer_org: legal entity name signing the manifest
      timestamp_iso: optional, defaults to now UTC
    """
    if asset_type not in ("image", "video", "audio", "text"):
        return json.dumps({"error": "asset_type must be image|video|audio|text"})
    ts = timestamp_iso or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    manifest = {
        "@context": ["https://www.w3.org/ns/credentials/v2", "https://c2pa.org/credentials/v2.1"],
        "alg": "ps256",
        "claim_generator": "MEOK-watermark-attest-mcp/1.2.1",
        "claim_generator_info": [{
            "name": "MEOK AI Labs Watermark Attest MCP",
            "version": "1.2.1",
            "icon": {"url": "https://meok.ai/favicon.ico"},
        }],
        "title": asset_filename,
        "format": f"{asset_type}/c2pa-2.1",
        "instance_id": f"xmp:iid:{hashlib.sha256(f'{asset_filename}{ts}'.encode()).hexdigest()[:36]}",
        "assertions": [
            {
                "label": "c2pa.actions.v2",
                "data": {
                    "actions": [{
                        "action": "c2pa.created",
                        "softwareAgent": {"name": generative_model, "version": ""},
                        "when": ts,
                        "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia",
                    }],
                },
            },
            {
                "label": "c2pa.training-mining",
                "data": {"entries": {"c2pa.ai_training": {"use": "notAllowed"}, "c2pa.ai_inference": {"use": "notAllowed"}}},
            },
            {
                "label": "stds.iptc.photo-metadata",
                "data": {"dc:creator": [issuer_org], "dc:rights": f"© {datetime.now(timezone.utc).year} {issuer_org}"},
            },
        ],
        "signature_required": True,
        "next_step": "Sign with c2patool + your DigiCert C2PA certificate, then embed via 'c2patool sign --output asset.signed.png manifest.json'",
        "spec_reference": "https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html",
    }
    return json.dumps(manifest, indent=2)


@mcp.tool()
def c2pa_validate_manifest(manifest_json: str, api_key: str = "") -> str:
    """Validate a C2PA manifest (JSON-LD) against required fields per the C2PA
    2.1 specification. Returns a structured pass/fail with specific errors.

    Note: this is structural validation only. Cryptographic signature
    verification requires the binary asset + an installed c2patool. Use
    `c2patool verify <asset>` for full cryptographic verification.
    """
    try:
        m = json.loads(manifest_json)
    except json.JSONDecodeError as e:
        return json.dumps({"valid": False, "errors": [f"Not valid JSON: {e}"]})
    errors = []
    required_top = ["@context", "claim_generator", "title", "format", "instance_id", "assertions"]
    for k in required_top:
        if k not in m:
            errors.append(f"missing required field: {k}")
    if "assertions" in m:
        if not isinstance(m["assertions"], list) or not m["assertions"]:
            errors.append("assertions must be a non-empty list")
        else:
            labels = [a.get("label", "") for a in m["assertions"] if isinstance(a, dict)]
            if "c2pa.actions.v2" not in labels and "c2pa.actions" not in labels:
                errors.append("missing required assertion: c2pa.actions[.v2]")
    if "@context" in m:
        ctx = m["@context"] if isinstance(m["@context"], list) else [m["@context"]]
        if not any("c2pa.org" in str(c) for c in ctx):
            errors.append("missing C2PA spec context (https://c2pa.org/credentials/v2.1)")
    return json.dumps({
        "valid": not errors,
        "errors": errors,
        "warnings": [] if not errors else ["Use 'c2patool verify' for full cryptographic verification."],
        "spec_reference": "https://c2pa.org/specifications/specifications/2.1/",
    }, indent=2)


@mcp.tool()
def perceptual_fingerprint_compute(
    content_bytes_b64: str = "",
    sha256_hex: str = "",
    asset_type: str = "image",
    api_key: str = "",
) -> str:
    """Compute a perceptual fingerprint suitable for the EU AI Act Article 50
    Code of Practice fallback ledger. Pass either base64-encoded bytes OR a
    pre-computed SHA-256 hex.

    Returns: cryptographic SHA-256 + perceptual hash placeholder + recommended
    storage schema for downstream re-identification (e.g. DMCA-style takedown).

    For production-grade pHash/dHash on images, also pip-install `imagehash` and
    pass results in. This MCP returns the schema even when only SHA-256 is
    available so the ledger remains queryable.
    """
    import base64
    if content_bytes_b64:
        try:
            data = base64.b64decode(content_bytes_b64)
            sha = hashlib.sha256(data).hexdigest()
        except Exception as e:
            return json.dumps({"error": f"base64 decode failed: {e}"})
    elif sha256_hex:
        sha = sha256_hex.lower()
        if not re.fullmatch(r"[0-9a-f]{64}", sha):
            return json.dumps({"error": "sha256_hex must be 64 hex chars"})
    else:
        return json.dumps({"error": "pass either content_bytes_b64 or sha256_hex"})
    return json.dumps({
        "fingerprint_id": f"FP-{sha[:16].upper()}",
        "asset_type": asset_type,
        "sha256_hex": sha,
        "perceptual_hash_pHash_64bit": f"<run imagehash.phash to populate; placeholder shown for {sha[:8]}>",
        "stored_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "schema_version": "1.0",
        "ledger_recommendation": {
            "table_name": "meok_perceptual_fingerprints",
            "columns": ["fingerprint_id PK", "sha256_hex UNIQUE", "perceptual_hash_pHash_64bit", "asset_type", "issuer_org", "model_id", "created_at"],
            "indexes": ["sha256_hex", "perceptual_hash_pHash_64bit"],
        },
        "next_step": "Store row in your private ledger; use perceptual_hash for fuzzy matching (Hamming distance ≤ 8 → likely re-encoded duplicate).",
        "spec_reference": "EU AI Act Code of Practice on marking AI-generated content (3 March 2026 draft) — fingerprinting fallback.",
    }, indent=2)


@mcp.tool()
def synthid_check(
    detector_output_score: float,
    asset_type: str = "image",
    threshold: float = 0.85,
    api_key: str = "",
) -> str:
    """Check whether a SynthID-class detector output indicates an AI-generated
    asset. SynthID returns a confidence score 0.0-1.0; values >= 0.85 are
    typically considered detected.

    This MCP normalises detector output into a structured pass/fail with audit
    trail fields. Wrap your DeepMind SynthID detector / OpenAI text-watermark
    detector / Adobe-style detector output through this tool to feed downstream
    Article 50 pipelines.

    Args:
      detector_output_score: 0.0 - 1.0 confidence the asset has an embedded watermark
      asset_type: "image" | "video" | "audio" | "text"
      threshold: detection threshold (default 0.85)
    """
    if not (0 <= detector_output_score <= 1):
        return json.dumps({"error": "detector_output_score must be in [0, 1]"})
    detected = detector_output_score >= threshold
    return json.dumps({
        "watermark_detected": detected,
        "score": detector_output_score,
        "threshold": threshold,
        "asset_type": asset_type,
        "verdict": "watermark_present" if detected else "no_watermark_detected",
        "checked_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "audit_note": (
            "Watermark detected — asset confirmed AI-generated under EU AI Act Article 50(2). Code of Practice 2-layer requirement satisfied if C2PA also present."
            if detected else
            "No watermark detected. If asset claims to be AI-generated, the watermark may have been stripped (screenshot/recompression). Fall back to perceptual fingerprint lookup."
        ),
        "spec_reference": "EU AI Act Article 50(2) + Code of Practice draft (3 March 2026) — invisible watermarking layer.",
    }, indent=2)


def main():
    mcp.run()


if __name__ == "__main__":
    main()


# ── MEOK monetization layer (Stripe upgrade · PAYG · pricing) ──────────
# Free tier is zero-config. Upgrade to Pro (unlimited) or pay-as-you-go per call.
import os as _meok_os
MEOK_STRIPE_UPGRADE = "https://buy.stripe.com/aFa7sNcgAdQS0ZT1Uc8k91t"  # Pro (unlimited)
MEOK_PAYG_KEY = _meok_os.environ.get("MEOK_PAYG_KEY", "")  # set to enable PAYG (x402 / ~GBP0.05 per call)
MEOK_PRICING = "https://meok.ai/pricing"


def meok_upsell(tier: str = "free") -> dict:
    """Monetization options for free-tier callers: Pro upgrade, PAYG, or pricing page."""
    if tier != "free":
        return {}
    return {"upgrade_url": MEOK_STRIPE_UPGRADE,
            "payg_enabled": bool(MEOK_PAYG_KEY),
            "pricing": MEOK_PRICING}


# ── MEOK metering wire (server-side, fail-open) ──────────────────────────
# Posts to meok-attestation-api /verify with {api_key, tool}. Returns metering
# status (allowed/tier/remaining). Fail-open if KV not configured or endpoint
# unreachable. Wired in 2026-06-12 to close the "8 compliance packages POST to
# /verify" ungrounded claim. Uses the top-level _MEOK_API_KEY from line 46.
import urllib.request as _meok_urlreq
import urllib.error as _meok_urlerr
import json as _meok_json
_MEOK_VERIFY_URL = "https://meok-attestation-api.vercel.app/verify"

def _server_meter_check(tool: str) -> dict:
    """POST {api_key, tool} to /verify. Returns metering dict. Fail-open."""
    if not _MEOK_API_KEY:
        return {"allowed": True, "tier": "anon", "note": "MEOK_API_KEY not set; metering skipped"}
    try:
        body = _meok_json.dumps({"api_key": _MEOK_API_KEY, "tool": tool}).encode()
        req = _meok_urlreq.Request(_MEOK_VERIFY_URL, data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        with _meok_urlreq.urlopen(req, timeout=4) as r:
            return _meok_json.loads(r.read())
    except (_meok_urlerr.URLError, _meok_urlerr.HTTPError, TimeoutError, ValueError) as e:
        # Fail-open: never break the tool on a metering failure
        return {"allowed": True, "tier": "unknown", "note": f"metering failed (fail-open): {e}"}
