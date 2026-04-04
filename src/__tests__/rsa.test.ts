import { describe, it, expect } from "vitest";
import {
  generateKeypair,
  exportKeys,
  importPublicKey,
  importPrivateKey,
  seal,
  open,
  serializeEnvelope,
  deserializeEnvelope,
  type RsaKeySize,
} from "../crypto/rsa";

describe("RSA-OAEP hybrid round-trip", () => {
  const keySizes: RsaKeySize[] = [2048, 4096];

  for (const bits of keySizes) {
    describe(`RSA-${bits}`, () => {
      for (let i = 1; i <= 5; i++) {
        it(`vector ${i}: seal then open recovers plaintext`, async () => {
          const message = `RSA-${bits} test #${i} — ${crypto.randomUUID()}`;
          const plaintext = new TextEncoder().encode(message);

          const kp = await generateKeypair(bits);
          const exported = await exportKeys(kp);

          // Seal with public key
          const envelope = await seal(kp.publicKey, plaintext);

          // Open with private key
          const recovered = await open(kp.privateKey, envelope);
          const decoded = new TextDecoder().decode(recovered);

          expect(decoded).toBe(message);

          // Verify key sizes are reasonable
          expect(exported.publicKeySpki.byteLength).toBeGreaterThan(100);
          expect(exported.privateKeyPkcs8.byteLength).toBeGreaterThan(100);
          expect(exported.publicKeyB64.length).toBeGreaterThan(0);

          // Wrapped key should be keySize/8 bytes
          expect(envelope.wrappedKey.length).toBe(bits / 8);
        });
      }

      it("serialization round-trip preserves envelope", async () => {
        const message = `RSA-${bits} serialization test`;
        const plaintext = new TextEncoder().encode(message);

        const kp = await generateKeypair(bits);
        const envelope = await seal(kp.publicKey, plaintext);

        const serialized = serializeEnvelope(envelope, bits);
        const deserialized = deserializeEnvelope(serialized, bits);

        const recovered = await open(kp.privateKey, deserialized);
        expect(new TextDecoder().decode(recovered)).toBe(message);
      });

      it("import/export round-trip preserves keys", async () => {
        const message = `RSA-${bits} import/export test`;
        const plaintext = new TextEncoder().encode(message);

        const kp = await generateKeypair(bits);
        const exported = await exportKeys(kp);

        const pubKey = await importPublicKey(exported.publicKeyB64);
        const privKey = await importPrivateKey(exported.privateKeyB64);

        const envelope = await seal(pubKey, plaintext);
        const recovered = await open(privKey, envelope);
        expect(new TextDecoder().decode(recovered)).toBe(message);
      });

      it("wrong private key fails to decrypt", async () => {
        const plaintext = new TextEncoder().encode("secret");
        const kp1 = await generateKeypair(bits);
        const kp2 = await generateKeypair(bits);

        const envelope = await seal(kp1.publicKey, plaintext);
        await expect(open(kp2.privateKey, envelope)).rejects.toThrow();
      });

      it("empty message round-trip works", async () => {
        const plaintext = new TextEncoder().encode("");
        const kp = await generateKeypair(bits);
        const envelope = await seal(kp.publicKey, plaintext);
        const recovered = await open(kp.privateKey, envelope);
        expect(new TextDecoder().decode(recovered)).toBe("");
      });

      it("rejects malformed public keys before import", async () => {
        await expect(importPublicKey("invalid+/=")).rejects.toThrow("base64url");
        await expect(importPublicKey("AQID")).rejects.toThrow("truncated or invalid");
      });

      it("rejects malformed private keys before import", async () => {
        await expect(importPrivateKey("AQID")).rejects.toThrow("truncated or invalid");
      });

      it("rejects truncated ciphertext payloads", () => {
        expect(() => deserializeEnvelope("AQID", bits)).toThrow("payload is too short");
      });
    });
  }
});
