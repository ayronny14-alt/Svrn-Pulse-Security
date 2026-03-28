# Security Policy

## Overview

`@svrnsec/pulse` is a hardware-physics fingerprinting library used as a security layer.
We take vulnerabilities seriously and will respond promptly.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.8.x   | :white_check_mark: Security fixes + active development |
| < 0.8   | :x: Deprecated — critical security vulnerabilities. Upgrade immediately. |

## Threat Model

**What pulse protects against:**
- Automated bots running in cloud VMs / Docker containers with no real hardware
- Headless browser automation (Puppeteer, Playwright) on virtual machines
- Credential-stuffing and account-takeover attacks from datacenter IP ranges
- Click farms (via proof-of-idle thermal cooling analysis)
- LLM-controlled browser agents (via behavioral biometrics)
- Coordinated inauthentic behavior (via population-level statistical analysis)
- Proof replay attacks (via HMAC-signed challenges + atomic nonce consumption)
- Payload tampering (via BLAKE3 commitment integrity)

**What pulse does NOT claim to protect against:**
- A determined human attacker on real consumer hardware
- A physical device farm where each device genuinely cools between interactions
- Kernel-level hooks that spoof `performance.now()` at nanosecond precision
- Server-side replay attacks when `checkNonce` is not wired (always wire it)
- GPU passthrough VMs with native hardware clock access

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Report security issues via email:

> **security@sovereign.dev**  *(or open a private GitHub Security Advisory)*

### What to include

1. A description of the vulnerability and the expected vs. actual behavior
2. Steps to reproduce (PoC code, scripts, or screenshots)
3. The impact — what can an attacker achieve?
4. Any suggested mitigation or fix

### Response SLA

| Severity | Initial response | Target fix |
|----------|-----------------|------------|
| Critical | 24 hours        | 7 days     |
| High     | 48 hours        | 14 days    |
| Medium   | 5 business days | 30 days    |
| Low      | 10 business days| Next minor |

We follow [coordinated disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure).
You will receive credit in the changelog unless you prefer to remain anonymous.

## Cryptographic Primitives

- **Hashing**: BLAKE3 via `@noble/hashes` — audited, constant-time implementation
- **Challenge signing**: HMAC-SHA256 over `nonce|issuedAt|expiresAt` with timing-safe comparison
- **Engagement tokens**: HMAC-SHA256 over fraud-relevant fields with 30-second TTL
- **Nonce generation**: `crypto.getRandomValues()` / Node.js `webcrypto` — 256 bits of entropy
- **Webhook signatures**: HMAC-SHA256 — standard authenticated integrity check
- **API key comparison**: `crypto.timingSafeEqual` — constant-time to prevent timing attacks

## Privacy

- Raw timing arrays never leave the device — server receives only a ~1.6 KB statistical summary
- Mouse coordinates are never stored — only timing deltas between events
- Keystrokes capture only dwell/flight times — key labels are discarded immediately
- `hardwareId()` is a 128-bit BLAKE3 hash — stable per device, not reversible, not cross-origin linkable
- No IP addresses are logged by default — integrators should implement their own IP handling policy

## Secure Deployment Checklist

- [ ] Set `NODE_ENV=production` to enforce secret validation at startup
- [ ] Set `PULSE_CHALLENGE_SECRET` to a cryptographically random 64-char hex string
- [ ] Set `WEBHOOK_SECRET` to a separate cryptographically random string
- [ ] Wire `checkNonce` to Redis `DEL` (returns 1 on first use) for atomic replay prevention
- [ ] Set `REDIS_URL` for multi-instance deployments (in-memory store is single-instance only)
- [ ] Put the API server behind TLS (nginx / Caddy / ALB)
- [ ] Set `CORS_ORIGINS` to your exact domain — not `*`
- [ ] Set `minJitterScore` >= 0.65 for high-value endpoints
- [ ] Monitor `riskFlags` in webhook payloads for anomaly detection
- [ ] Use `/health/ready` (not `/health`) for load balancer health checks
- [ ] Rotate `PULSE_API_KEYS` regularly; use different keys per environment
- [ ] Review `webhook.dead_letter` log events for delivery failures
