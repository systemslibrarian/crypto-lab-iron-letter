// ── RSA-OAEP Hybrid (WebCrypto) ──────────────────────────────────────
// RSA-OAEP wraps a random AES-256-GCM key; AES encrypts the message.

import { toBase64Url, fromBase64Url } from "./ecies";

const HASH = "SHA-256";
const AES_KEY_BITS = 256;
const IV_BYTES = 12;

export type RsaKeySize = 2048 | 4096;

export interface RsaKeypair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
  keySize: RsaKeySize;
}

export interface RsaExported {
  publicKeySpki: ArrayBuffer;
  publicKeyB64: string;
  privateKeyPkcs8: ArrayBuffer;
  privateKeyB64: string;
}

export interface RsaCiphertext {
  wrappedKey: Uint8Array; // RSA-OAEP encrypted AES key
  iv: Uint8Array; // 12 bytes
  ciphertext: Uint8Array; // AES-GCM ciphertext
}

// ── helpers ──────────────────────────────────────────────────────────

function concat(...arrays: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result as Uint8Array<ArrayBuffer>;
}

// ── 2.1 / 2.2  Keypair generation ───────────────────────────────────

export async function generateKeypair(bits: RsaKeySize): Promise<RsaKeypair> {
  const kp = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: bits,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: HASH,
    },
    true,
    ["wrapKey", "unwrapKey"]
  );
  return { publicKey: kp.publicKey, privateKey: kp.privateKey, keySize: bits };
}

// ── 2.3 / 2.4  Key export ───────────────────────────────────────────

export async function exportKeys(kp: RsaKeypair): Promise<RsaExported> {
  const [publicKeySpki, privateKeyPkcs8] = await Promise.all([
    crypto.subtle.exportKey("spki", kp.publicKey),
    crypto.subtle.exportKey("pkcs8", kp.privateKey),
  ]);
  return {
    publicKeySpki,
    publicKeyB64: toBase64Url(publicKeySpki),
    privateKeyPkcs8,
    privateKeyB64: toBase64Url(privateKeyPkcs8),
  };
}

// ── 2.7  Hybrid RSA seal ────────────────────────────────────────────

export async function seal(
  recipientPubKey: CryptoKey,
  plaintext: BufferSource
): Promise<RsaCiphertext> {
  // Generate random AES key
  const aesKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: AES_KEY_BITS },
    true,
    ["encrypt"]
  );

  // RSA-OAEP wrap the AES key
  const wrappedKey = await crypto.subtle.wrapKey(
    "raw",
    aesKey,
    recipientPubKey,
    { name: "RSA-OAEP" }
  );

  // AES-GCM encrypt
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES)) as Uint8Array<ArrayBuffer>;
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, plaintext);

  return {
    wrappedKey: new Uint8Array(wrappedKey),
    iv,
    ciphertext: new Uint8Array(ct),
  };
}

// ── 2.8  Hybrid RSA open ────────────────────────────────────────────

export async function open(
  recipientPrivKey: CryptoKey,
  envelope: RsaCiphertext
): Promise<Uint8Array> {
  // Unwrap AES key
  const aesKey = await crypto.subtle.unwrapKey(
    "raw",
    envelope.wrappedKey as Uint8Array<ArrayBuffer>,
    recipientPrivKey,
    { name: "RSA-OAEP" },
    { name: "AES-GCM", length: AES_KEY_BITS },
    false,
    ["decrypt"]
  );

  // AES-GCM decrypt
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: envelope.iv as Uint8Array<ArrayBuffer> },
    aesKey,
    envelope.ciphertext as Uint8Array<ArrayBuffer>
  );
  return new Uint8Array(pt);
}

// ── Serialization ────────────────────────────────────────────────────

export function serializeEnvelope(env: RsaCiphertext, _keySize: RsaKeySize): string {
  // wrappedKey length = keySize / 8
  const packed = concat(env.wrappedKey, env.iv, env.ciphertext);
  return toBase64Url(packed.buffer as ArrayBuffer);
}

export function deserializeEnvelope(s: string, keySize: RsaKeySize): RsaCiphertext {
  const data = fromBase64Url(s);
  const wkLen = keySize / 8;
  return {
    wrappedKey: data.slice(0, wkLen),
    iv: data.slice(wkLen, wkLen + IV_BYTES),
    ciphertext: data.slice(wkLen + IV_BYTES),
  };
}

// ── Import keys from base64url ───────────────────────────────────────

export async function importPublicKey(b64: string): Promise<CryptoKey> {
  const spki = fromBase64Url(b64);
  return crypto.subtle.importKey(
    "spki",
    spki,
    { name: "RSA-OAEP", hash: HASH },
    true,
    ["wrapKey"]
  );
}

export async function importPrivateKey(b64: string): Promise<CryptoKey> {
  const pkcs8 = fromBase64Url(b64);
  return crypto.subtle.importKey(
    "pkcs8",
    pkcs8,
    { name: "RSA-OAEP", hash: HASH },
    true,
    ["unwrapKey"]
  );
}
