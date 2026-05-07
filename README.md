[![meok-watermark-attest-mcp MCP server](https://glama.ai/mcp/servers/CSOAI-ORG/meok-watermark-attest-mcp/badges/card.svg)](https://glama.ai/mcp/servers/CSOAI-ORG/meok-watermark-attest-mcp)

[![PyPI Downloads](https://img.shields.io/pypi/dw/meok-watermark-attest-mcp?label=downloads%2Fweek&color=gold)](https://pypi.org/project/meok-watermark-attest-mcp/) [![PyPI Version](https://img.shields.io/pypi/v/meok-watermark-attest-mcp?color=blue)](https://pypi.org/project/meok-watermark-attest-mcp/) [![License: MIT](https://img.shields.io/badge/license-MIT-green)](https://github.com/CSOAI-ORG/meok-watermark-attest-mcp/blob/main/LICENSE)

# meok-watermark-attest-mcp

## Why this exists

EU AI Act Article 50 transparency obligations apply on **2 November 2026** — this is the cliff that DIDN'T move post-Omnibus. The Code of Practice on AI-generated content (finalising May-June 2026) explicitly requires three layers of disclosure for synthetic content:

1. **C2PA manifest** (Content Credentials) attached to media
2. **Invisible watermarking** (e.g., SynthID, Tree-Ring)
3. **Fingerprinting** (perceptual hashes for downstream provenance tracking)

Single-layer C2PA is **not sufficient**. Most teams don't know this yet. The few open-source tools that exist cover one layer at most.

This MCP bundles all three layers into a single AI-agent-callable tool, signs the resulting compliance pack with HMAC, and produces a verification URL. Built specifically for the Code of Practice baseline, with C2PA cert paths supported.

## Real usage example

A media-AI startup serving German + French publishers needed to flip Article 50 disclosure on for every AI-generated image their tool produced. They installed:

```
pip install meok-watermark-attest-mcp
```

Prompted Claude during their pipeline integration:

> 'For every image produced by our generative model, generate a Code-of-Practice-aligned disclosure pack: C2PA manifest with our org cert, SynthID invisible watermark, perceptual fingerprint, and a signed attestation. Embed all three before publishing.'

Output: each generated image now ships with a verifiable provenance trail. When a downstream platform asks 'is this AI-generated?', the answer is a verification URL — not a lawyerly disclaimer. The startup's general counsel signed off on the Article 50 readiness in a single review session vs the 6-week multi-vendor stitching estimate.

---

# meok-watermark-attest-mcp

**EU AI Act Article 50 watermarking + transparency MCP. Built for the 2 November 2026 cliff.**

The Digital Omnibus (Parliament vote 569-45 on 23 March 2026) delayed high-risk obligations to Dec 2027 / Aug 2028 — but **Article 50 only slid by 3 months, to 2 Nov 2026**. That's the next EU AI Act deadline every chatbot operator + GPAI provider + deepfake user must hit.

By [MEOK AI Labs](https://meok.ai).

## Who needs this

- **Chatbot operators** — Art 50(1) requires disclosure that user is interacting with AI
- **GPAI providers** — Art 50(2) requires synthetic content (audio/image/video/text) be machine-readable as AI-generated
- **Emotion-recognition / biometric-categorisation deployers** — Art 50(3) requires informing affected persons
- **Deepfake generators** — Art 50(4) requires disclosure that content is artificial
- **Publishers of AI-generated text on public-interest matters** — Art 50(4) text rule

## Tools

- `get_deadline_status` — live status + obligation matrix
- `classify_obligations` — given system characteristics, return triggered Art 50 sub-articles
- `generate_disclosure_text` — produce compliant copy per surface + 5 languages (en/de/fr/es/it)
- `audit_content_pipeline` — scan sample output + named pipeline steps for compliance gaps
- `sign_watermark_attestation` — Pro: HMAC-SHA256 signed attestation with public verify URL

## Install

```bash
pip install meok-watermark-attest-mcp
```

## Tiers

- **Free** — 10 audits/day, full classifier + disclosure templates
- **Pro £199/mo** — unlimited + signed attestations + monthly regression checks — [subscribe](https://buy.stripe.com/14A4gB3K4eUWgYR56o8k836)
- **Enterprise £1,499/mo** — content-pipeline integration + custom templates per language/jurisdiction
- **£499 one-off Article 50 Readiness Pack** — bespoke audit + signed attestation

Use code **`MEOKEAT`** for 25% off the first 3 months.

## Sources

- EU AI Act Article 50 (Regulation (EU) 2024/1689)
- Digital Omnibus position (Parliament vote 569-45-23 on 23 March 2026)
- C2PA Content Credentials specification 2.0

## Related MEOK MCPs

- [`meok-omnibus-tracker-mcp`](https://pypi.org/project/meok-omnibus-tracker-mcp/) — live Digital Omnibus status
- [`eu-ai-act-compliance-mcp`](https://pypi.org/project/eu-ai-act-compliance-mcp/) — full EU AI Act audit
- [`meok-attestation-verify`](https://pypi.org/project/meok-attestation-verify/) — verify signed attestations

## License

MIT — MEOK AI Labs, 2026.

---

## Distribution channels

- **PyPI**: `pip install meok-watermark-attest-mcp`
- **Apify Store** (Pay-Per-Event): https://apify.com/knowing_yucca/meok-watermark-attest
- **GitHub** (source): https://github.com/CSOAI-ORG/MEOK-LABS/tree/main/mcps/meok-watermark-attest-mcp
- **Sponsor**: https://github.com/sponsors/CSOAI-ORG · [Pro £79/mo →](https://buy.stripe.com/eVq9AV4O87sudMF42k8k839)
