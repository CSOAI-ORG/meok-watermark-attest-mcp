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

## Full Compliance Platform

Article 50 is just one piece. **[councilof.ai](https://councilof.ai)** covers the full EU AI Act + DORA + NIS2 + CRA stack from £29/mo.

→ **[Get started at councilof.ai](https://councilof.ai)**

## Related MEOK MCPs

- [`meok-omnibus-tracker-mcp`](https://pypi.org/project/meok-omnibus-tracker-mcp/) — live Digital Omnibus status
- [`eu-ai-act-compliance-mcp`](https://pypi.org/project/eu-ai-act-compliance-mcp/) — full EU AI Act audit
- [`meok-attestation-verify`](https://pypi.org/project/meok-attestation-verify/) — verify signed attestations

## License

MIT — [MEOK AI Labs](https://meok.ai), 2026.

<!-- mcp-name: io.github.CSOAI-ORG/meok-watermark-attest-mcp -->
