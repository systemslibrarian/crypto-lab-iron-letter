# crypto-lab-iron-letter

## What It Is

Iron Letter is a browser-based demo of ECIES P-256 and RSA-OAEP hybrid encryption built on the Web Crypto API. ECIES P-256 combines ECDH, HKDF-SHA256, and AES-256-GCM, while RSA-2048 and RSA-4096 use RSA-OAEP to wrap an AES-256-GCM content key. The problem it solves is public-key message sealing, where anyone can encrypt to a recipient but only the matching private key can decrypt. This is an asymmetric security model, with symmetric AES used inside each hybrid envelope for message confidentiality and integrity.

## When to Use It

- Use it to teach or compare asymmetric envelope-encryption designs, because it shows ECIES P-256 and RSA-OAEP metrics side by side under the same runtime conditions.
- Use it for client-side experimentation with WebCrypto key generation and ciphertext formats, because all cryptographic operations happen locally in the browser.
- Use it to demonstrate shareable public-key workflows, because the app can encode public keys into URLs and QR codes without exposing private keys.
- Do not use it as-is for production key management or compliance-sensitive systems, because it is a demo app and does not provide hardened operational controls.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-iron-letter](https://systemslibrarian.github.io/crypto-lab-iron-letter/)**

The demo lets you generate keypairs, seal messages, and open ciphertext for ECIES P-256, RSA-2048, and RSA-4096. You can switch algorithm tabs, inspect timing and size metrics, and compare public-key and ciphertext characteristics in the comparison view. The Compare tab's **Run Benchmark** button generates a keypair for each algorithm and averages encrypt/decrypt timings over many iterations in a single click, and surfaces each algorithm's approximate security level (NIST SP 800-57) so the key trade-off is explicit — ECIES P-256's 65-byte key is stronger than RSA-2048's far larger one. It also includes controls for copying share URLs, copying ciphertext, and generating QR codes for public keys.

## What Can Go Wrong

- Nonce/IV reuse in AES-256-GCM breaks both confidentiality and authentication, so each message needs a fresh, unique nonce.
- Encrypting to an unauthenticated public key invites a man-in-the-middle who substitutes their own key — the recipient's key must be bound to a verified identity.
- Public-key encryption alone provides no sender authentication; anyone can encrypt to a recipient, so a separate signature is needed to prove origin.
- ECIES and RSA-OAEP depend on matching curve/KDF/AEAD and padding parameters between sender and recipient — a mismatch causes decryption failure or weakened security.
- Private keys generated and held in the browser are only as safe as the device and session; this demo is not a key-management system.

## Real-World Usage

- Hybrid encryption (a public-key wrap of a symmetric content key) is how real systems seal data — PGP/GPG, S/MIME, age, and JOSE/JWE all follow this pattern.
- ECIES-style schemes underpin encrypted messaging and many wallet/blockchain encryption flows.
- RSA-OAEP key wrapping appears in document encryption, legacy TLS, and KMS envelope encryption.
- The ECC-versus-RSA key-size and performance trade-off shown here drives real protocol and platform choices, especially on constrained or high-volume systems.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-iron-letter
cd crypto-lab-iron-letter
npm install
npm run dev
```

## Related Demos

- [crypto-lab-rsa-forge](https://systemslibrarian.github.io/crypto-lab-rsa-forge/) — the RSA primitive behind RSA-OAEP, with OAEP/PSS/PKCS#1 attacks.
- [crypto-lab-envelope-kms](https://systemslibrarian.github.io/crypto-lab-envelope-kms/) — DEK/KEK envelope encryption and key wrapping in the large.
- [crypto-lab-ibe-gate](https://systemslibrarian.github.io/crypto-lab-ibe-gate/) — identity-based public-key encryption, an alternative sealing model.
- [crypto-lab-elgamal-plain](https://systemslibrarian.github.io/crypto-lab-elgamal-plain/) — another asymmetric encryption scheme with homomorphic structure.
- [crypto-lab-curve-lens](https://systemslibrarian.github.io/crypto-lab-curve-lens/) — the ECDH key agreement at the heart of ECIES.

---

*One of 60+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
