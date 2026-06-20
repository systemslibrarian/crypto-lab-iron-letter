# Iron Letter

## What It Is

Iron Letter is a browser-based demo of ECIES P-256 and RSA-OAEP hybrid encryption built on the Web Crypto API. ECIES P-256 combines ECDH, HKDF-SHA256, and AES-256-GCM, while RSA-2048 and RSA-4096 use RSA-OAEP to wrap an AES-256-GCM content key. The problem it solves is public-key message sealing, where anyone can encrypt to a recipient but only the matching private key can decrypt. This is an asymmetric security model, with symmetric AES used inside each hybrid envelope for message confidentiality and integrity.

## When to Use It

- Use it to teach or compare asymmetric envelope-encryption designs, because it shows ECIES P-256 and RSA-OAEP metrics side by side under the same runtime conditions.
- Use it for client-side experimentation with WebCrypto key generation and ciphertext formats, because all cryptographic operations happen locally in the browser.
- Use it to demonstrate shareable public-key workflows, because the app can encode public keys into URLs and QR codes without exposing private keys.
- Do not use it as-is for production key management or compliance-sensitive systems, because it is a demo app and does not provide hardened operational controls.

## Live Demo

**[Live Demo](https://systemslibrarian.github.io/crypto-lab-iron-letter/)**

The demo lets you generate keypairs, seal messages, and open ciphertext for ECIES P-256, RSA-2048, and RSA-4096. You can switch algorithm tabs, inspect timing and size metrics, and compare public-key and ciphertext characteristics in the comparison view. The Compare tab's **Run Benchmark** button generates a keypair for each algorithm and averages encrypt/decrypt timings over many iterations in a single click, and surfaces each algorithm's approximate security level (NIST SP 800-57) so the key trade-off is explicit — ECIES P-256's 65-byte key is stronger than RSA-2048's far larger one. It also includes controls for copying share URLs, copying ciphertext, and generating QR codes for public keys.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-iron-letter.git
cd crypto-lab-iron-letter
npm install
npm run dev
```

No environment variables are required.

## Part of the Crypto-Lab Suite

Iron Letter is one module in the broader Crypto-Lab collection at https://systemslibrarian.github.io/crypto-lab/.

Whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31
