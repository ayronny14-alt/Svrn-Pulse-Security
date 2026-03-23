# Security Policy

## Overview

`@sovereign/pulse` is a hardware-physics fingerprinting library used as a security layer.
We take vulnerabilities seriously and will respond promptly.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | ✅ Current release |
| < 0.1   | ❌ No longer supported |

## Threat Model

**What pulse protects against:**
- Automated bots running in cloud VMs / Docker containers with no real hardware
- Headless browser automation (Puppeteer, Playwright) on virtual machines
- Credential-stuffing and account-takeover attacks from datacenter IP ranges

**What pulse does NOT claim to protect against:**
- A determined human attacker on real consumer hardware
- A physical device farm (phones/laptops in a room)
- Kernel-level hooks that spoof `performance.now()` at nanosecond precision
- Server-side replay attacks when `checkNonce` is not wired (always wire it)

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
- **Nonce generation**: `crypto.getRandomValues()` / Node.js `webcrypto` — 256 bits of entropy
- **Webhook signatures**: HMAC-SHA256 — standard authenticated integrity check

## Known Limitations & Design Decisions

### Score, not binary gate
The jitter score is a continuous value `[0, 1]`.  Applications must choose their own
threshold (`minJitterScore`).  A score of `0.55` (default) is conservative; financial
applications may want `0.70+`.

### No raw data leaves the browser
The server receives only a ~1.6 KB statistical summary (means, variances, percentiles).
Raw timing arrays and mouse coordinates stay on device.  This is intentional — it
limits what a compromised server can learn about the client.

### Registry is additive
The VM classification registry (which vendor a VM is from) is separate from detection.
A VM can be detected by physics even if its vendor is not in the registry.

## Secure Deployment Checklist

- [ ] Set `NODE_ENV=production` to disable verbose error messages
- [ ] Wire `checkNonce` to a Redis `SET NX` with TTL to prevent replay attacks
- [ ] Set `PULSE_WEBHOOK_SECRET` to a cryptographically random 32+ character string
- [ ] Put the API server behind TLS (nginx / Caddy / ALB)
- [ ] Set `PULSE_CORS_ORIGINS` to your exact domain — not `*`
- [ ] Set `minJitterScore` ≥ 0.65 for high-value endpoints
- [ ] Monitor `riskFlags` in webhook payloads for anomaly detection
- [ ] Rotate `PULSE_API_KEYS` regularly; use different keys per environment
