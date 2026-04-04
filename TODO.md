# Iron Letter Build Progress

Last updated: 2026-04-04
Last commit: (none yet)

## PHASE 0 — Scaffold
- [x] 0.1 Create TODO.md
- [x] 0.2 Vite + TypeScript init
- [x] 0.3 Tailwind CSS setup
- [x] 0.4 GitHub Actions deploy workflow
- [x] 0.5 Project structure created
- [x] 0.6 Environment verified (npm run dev works)
- [ ] 0.7 Phase 0 commit

## PHASE 1 — ECIES Implementation
- [x] 1.1 ECDH keypair generation (P-256, WebCrypto)
- [x] 1.2 Public key export (raw 65 bytes + base64url)
- [x] 1.3 Private key export (PKCS8 + base64url)
- [x] 1.4 ECDH shared secret derivation
- [x] 1.5 HKDF key expansion from shared secret
- [x] 1.6 AES-256-GCM encrypt with derived key
- [x] 1.7 AES-256-GCM decrypt with derived key
- [x] 1.8 ECIES seal (full pipeline: ephemeral keypair → ECDH → HKDF → AES-GCM)
- [x] 1.9 ECIES open (full pipeline: ECDH → HKDF → AES-GCM decrypt)
- [x] 1.10 ECIES round-trip test (10 vectors)
- [ ] 1.11 Phase 1 commit

## PHASE 2 — RSA-OAEP Implementation
- [x] 2.1 RSA-OAEP-2048 keypair generation (WebCrypto)
- [x] 2.2 RSA-OAEP-4096 keypair generation (WebCrypto)
- [x] 2.3 Public key export (SPKI + base64url)
- [x] 2.4 Private key export (PKCS8 + base64url)
- [x] 2.5 RSA-OAEP encrypt (public key + plaintext → ciphertext)
- [x] 2.6 RSA-OAEP decrypt (private key + ciphertext → plaintext)
- [x] 2.7 Hybrid RSA: RSA-OAEP wraps AES key, AES-GCM encrypts message
- [x] 2.8 RSA-OAEP round-trip test (10 vectors)
- [ ] 2.9 Phase 2 commit

## PHASE 3 — Key URL System
- [x] 3.1 Public key → shareable URL encoding
- [x] 3.2 URL → public key decoding + validation
- [x] 3.3 Deep link: /?pk={base64url_public_key}&algo={ecies|rsa2048|rsa4096}
- [x] 3.4 URL copy to clipboard
- [x] 3.5 QR code generation (pure JS — no external service)
- [ ] 3.6 Phase 3 commit

## PHASE 4 — Metrics Engine
- [x] 4.1 Keygen time measurement (performance.now())
- [x] 4.2 Public key size in bytes
- [x] 4.3 Private key size in bytes
- [x] 4.4 Ciphertext size in bytes
- [x] 4.5 Encrypt time measurement
- [x] 4.6 Decrypt time measurement
- [x] 4.7 Live metrics update on every operation
- [ ] 4.8 Phase 4 commit

## PHASE 5 — UI
- [x] 5.1 CSS design system (vault-adjacent dark aesthetic)
- [x] 5.2 Tab layout (ECIES | RSA-2048 | RSA-4096 | Compare)
- [x] 5.3 Keygen panel (generate, display key sizes + time)
- [x] 5.4 Seal panel (input message, encrypt, show ciphertext)
- [x] 5.5 Open panel (paste ciphertext + private key, decrypt)
- [x] 5.6 Comparison panel (side-by-side metrics table)
- [x] 5.7 Shareable URL panel (copy link, QR code)
- [x] 5.8 How It Works modal (ECIES pipeline diagram, RSA hybrid explanation)
- [x] 5.9 Key size visual (bar chart — 65 bytes vs 800 bytes, same security)
- [x] 5.10 Boot self-test (WebCrypto available check)
- [x] 5.11 Accessibility
- [ ] 5.12 Phase 5 commit

## PHASE 6 — Hardening
- [x] 6.1 TypeScript strict: npx tsc --noEmit exits 0
- [ ] 6.2 No console errors: Chrome, Firefox, Safari
- [x] 6.3 Mobile responsive at 375px
- [x] 6.4 prefers-reduced-motion respected
- [x] 6.5 Private key never leaves browser (verified via network tab)
- [x] 6.6 README.md complete
- [ ] 6.7 crypto-compare integration (Asymmetric Encryption category)
- [x] 6.8 GitHub Actions build passes
- [ ] 6.9 Live URL resolves, full round-trip works
- [ ] 6.10 Phase 6 commit — DONE
