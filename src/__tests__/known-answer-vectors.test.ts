import { describe, expect, it } from "vitest";
import {
  deserializeEnvelope as deserializeEciesEnvelope,
  importPrivateKey as importEciesPrivateKey,
  importPublicKey as importEciesPublicKey,
  open as openEcies,
  serializeEnvelope as serializeEciesEnvelope,
  fromBase64Url,
} from "../crypto/ecies";
import {
  deserializeEnvelope as deserializeRsaEnvelope,
  importPrivateKey as importRsaPrivateKey,
  importPublicKey as importRsaPublicKey,
  open as openRsa,
  serializeEnvelope as serializeRsaEnvelope,
} from "../crypto/rsa";
import { knownAnswerVectors } from "./fixtures";

describe("known-answer vectors", () => {
  it("decrypts the fixed ECIES ciphertext", async () => {
    const vector = knownAnswerVectors.ecies;
    const privateKey = await importEciesPrivateKey(vector.privateKeyB64);
    const publicKey = await importEciesPublicKey(vector.publicKeyB64);
    const envelope = deserializeEciesEnvelope(vector.ciphertext);
    const plaintext = await openEcies(privateKey, envelope);

    expect(new TextDecoder().decode(plaintext)).toBe(vector.message);
    expect(serializeEciesEnvelope(envelope)).toBe(vector.ciphertext);
    expect(fromBase64Url(vector.publicKeyB64).byteLength).toBe(vector.publicKeyBytes);
    expect(fromBase64Url(vector.privateKeyB64).byteLength).toBe(vector.privateKeyBytes);
    expect(publicKey.algorithm.name).toBe("ECDH");
    expect(privateKey.algorithm.name).toBe("ECDH");
  });

  it("decrypts the fixed RSA-2048 ciphertext", async () => {
    const vector = knownAnswerVectors.rsa2048;
    const privateKey = await importRsaPrivateKey(vector.privateKeyB64);
    const publicKey = await importRsaPublicKey(vector.publicKeyB64);
    const envelope = deserializeRsaEnvelope(vector.ciphertext, 2048);
    const plaintext = await openRsa(privateKey, envelope);

    expect(new TextDecoder().decode(plaintext)).toBe(vector.message);
    expect(serializeRsaEnvelope(envelope, 2048)).toBe(vector.ciphertext);
    expect(fromBase64Url(vector.publicKeyB64).byteLength).toBe(vector.publicKeyBytes);
    expect(fromBase64Url(vector.privateKeyB64).byteLength).toBe(vector.privateKeyBytes);
    expect(publicKey.algorithm.name).toBe("RSA-OAEP");
    expect(privateKey.algorithm.name).toBe("RSA-OAEP");
  });

  it("decrypts the fixed RSA-4096 ciphertext", async () => {
    const vector = knownAnswerVectors.rsa4096;
    const privateKey = await importRsaPrivateKey(vector.privateKeyB64);
    const publicKey = await importRsaPublicKey(vector.publicKeyB64);
    const envelope = deserializeRsaEnvelope(vector.ciphertext, 4096);
    const plaintext = await openRsa(privateKey, envelope);

    expect(new TextDecoder().decode(plaintext)).toBe(vector.message);
    expect(serializeRsaEnvelope(envelope, 4096)).toBe(vector.ciphertext);
    expect(fromBase64Url(vector.publicKeyB64).byteLength).toBe(vector.publicKeyBytes);
    expect(fromBase64Url(vector.privateKeyB64).byteLength).toBe(vector.privateKeyBytes);
    expect(publicKey.algorithm.name).toBe("RSA-OAEP");
    expect(privateKey.algorithm.name).toBe("RSA-OAEP");
  });
});