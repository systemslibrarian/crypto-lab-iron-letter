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
} from "../crypto/ecies";

describe("ECIES P-256 round-trip", () => {
  for (let i = 1; i <= 10; i++) {
    it(`vector ${i}: seal then open recovers plaintext`, async () => {
      const message = `Test message #${i} — ${crypto.randomUUID()}`;
      const plaintext = new TextEncoder().encode(message);

      // Generate recipient keypair
      const kp = await generateKeypair();
      const exported = await exportKeys(kp);

      // Seal with public key
      const envelope = await seal(kp.publicKey, plaintext);

      // Open with private key
      const recovered = await open(kp.privateKey, envelope);
      const decoded = new TextDecoder().decode(recovered);

      expect(decoded).toBe(message);

      // Verify key sizes
      expect(exported.publicKeyRaw.byteLength).toBe(65);
      expect(exported.publicKeyB64.length).toBeGreaterThan(0);
      expect(exported.privateKeyPkcs8.byteLength).toBeGreaterThan(0);
    });
  }

  it("serialization round-trip preserves envelope", async () => {
    const message = "Serialization test";
    const plaintext = new TextEncoder().encode(message);

    const kp = await generateKeypair();
    const envelope = await seal(kp.publicKey, plaintext);

    // Serialize and deserialize
    const serialized = serializeEnvelope(envelope);
    const deserialized = deserializeEnvelope(serialized);

    // Open with deserialized envelope
    const recovered = await open(kp.privateKey, deserialized);
    expect(new TextDecoder().decode(recovered)).toBe(message);
  });

  it("import/export round-trip preserves keys", async () => {
    const message = "Import/export test";
    const plaintext = new TextEncoder().encode(message);

    const kp = await generateKeypair();
    const exported = await exportKeys(kp);

    // Re-import keys from base64url
    const pubKey = await importPublicKey(exported.publicKeyB64);
    const privKey = await importPrivateKey(exported.privateKeyB64);

    // Seal with re-imported public key
    const envelope = await seal(pubKey, plaintext);

    // Open with re-imported private key
    const recovered = await open(privKey, envelope);
    expect(new TextDecoder().decode(recovered)).toBe(message);
  });

  it("wrong private key fails to decrypt", async () => {
    const plaintext = new TextEncoder().encode("secret");
    const kp1 = await generateKeypair();
    const kp2 = await generateKeypair();

    const envelope = await seal(kp1.publicKey, plaintext);

    await expect(open(kp2.privateKey, envelope)).rejects.toThrow();
  });

  it("empty message round-trip works", async () => {
    const plaintext = new TextEncoder().encode("");
    const kp = await generateKeypair();
    const envelope = await seal(kp.publicKey, plaintext);
    const recovered = await open(kp.privateKey, envelope);
    expect(new TextDecoder().decode(recovered)).toBe("");
  });
});
