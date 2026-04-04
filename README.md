# Iron Letter

Asymmetric encryption in the browser — ECIES P-256 vs RSA-OAEP, side by side.  
Seal a letter. Only one key can open it.

**[Live Demo](https://systemslibrarian.github.io/iron-letter/)**

## What it does

Iron Letter is a zero-dependency cryptography demo that runs entirely in the browser using the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API). It implements three asymmetric encryption schemes and lets you compare them head-to-head:

| Algorithm | Public Key | Security Level | Approach |
|-----------|-----------|---------------|----------|
| **ECIES P-256** | 65 bytes | 128-bit | ECDH + HKDF + AES-256-GCM |
| **RSA-2048** | ~294 bytes | 112-bit | RSA-OAEP wraps AES-256-GCM key |
| **RSA-4096** | ~550 bytes | 128-bit | RSA-OAEP wraps AES-256-GCM key |

### Features

- **Key generation** with timing and size metrics
- **Encrypt / decrypt** round-trip in each scheme
- **Strict input validation** for malformed keys and truncated payloads
- **Startup self-check** that verifies ECIES and RSA pipelines before use
- **Known-answer vectors** for fixed ECIES, RSA-2048, and RSA-4096 ciphertexts
- **Side-by-side comparison** table with bar charts
- **Shareable public key URLs** with QR codes
- **Deep linking** — send someone a URL pre-loaded with your public key
- **How It Works** modal explaining both pipelines
- **No server, no dependencies** — all crypto is WebCrypto, all rendering is vanilla TS

## Getting started

```bash
npm install
npm run dev
```

Open `http://localhost:5173/iron-letter/` in a browser.

## Build & deploy

```bash
npm run build   # outputs to dist/
npm test        # unit + crypto validation tests
npm run test:e2e
```

GitHub Pages deployment is configured via `.github/workflows/deploy.yml` — pushes to `main` auto-deploy.

## Architecture

```
src/
├── crypto/
│   ├── ecies.ts      # ECIES P-256: ECDH + HKDF-SHA256 + AES-256-GCM
│   ├── rsa.ts         # RSA-OAEP hybrid: RSA wraps AES key
│   └── metrics.ts     # Timing and size measurement utilities
├── keyurl.ts          # Public key ↔ shareable URL encoding
├── qr.ts              # Pure JS QR code generator (SVG output)
├── main.ts            # UI rendering, event handling, state management
├── style.css          # Tailwind CSS entry
└── vite-env.d.ts      # Vite type declarations
```

## Security notes

- Private keys are generated and used entirely in the browser via `crypto.subtle`
- No keys are ever transmitted over the network
- Share URLs contain only **public** keys
- All encryption uses authenticated encryption (AES-256-GCM)
- ECIES uses ephemeral keypairs — a fresh ECDH keypair per message
- Malformed keys and truncated ciphertexts are rejected before WebCrypto operations run
- Startup performs a real ECIES and RSA round-trip self-check before showing the demo as healthy
- A strict GitHub Pages-compatible CSP and `no-referrer` policy are set via document meta tags

## Tech stack

- **Vite** + **TypeScript** (strict mode)
- **Tailwind CSS** v4
- **Web Crypto API** — zero external crypto dependencies
