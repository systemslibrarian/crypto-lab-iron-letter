/**
 * A bounded educational implementation of the IMSI-based SUCI protection
 * scheme. ETSI TS 133 501 V19.7.0 (2026-08), clauses 6.12.2 and Annex C.
 * Profile A is X25519 + ANSI X9.63 KDF/SHA-256 + AES-128-CTR + an 8-byte
 * truncated HMAC-SHA-256. This does not encode a complete 5G NAS message.
 */

export const SUCI_SPEC =
  "https://www.etsi.org/deliver/etsi_ts/133500_133599/133501/19.07.00_60/ts_133501v190700p.pdf";

export interface ProfileAOutput {
  ephemeralPublic: Uint8Array;
  ciphertext: Uint8Array;
  mac: Uint8Array;
  schemeOutput: Uint8Array;
}

function bytes(...parts: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

// TypeScript's BufferSource requires ArrayBuffer-backed views; copy rather than
// assuming callers' Uint8Arrays cannot be backed by SharedArrayBuffer.
function webBytes(data: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(data.length);
  copy.set(data);
  return copy;
}

export function hex(data: Uint8Array): string {
  return Array.from(data, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function fromHex(value: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})*$/i.test(value)) throw new Error("Expected an even-length hex string");
  return new Uint8Array(value.match(/../g)?.map((part) => parseInt(part, 16)) ?? []);
}

/** TS 33.501 C.3.1 packs decimal MSIN digits low nibble first; F pads an odd final digit. */
export function packMsin(msin: string): Uint8Array {
  if (!/^\d{1,10}$/.test(msin)) throw new Error("Enter 1–10 decimal subscriber digits (MSIN).");
  const packed = new Uint8Array(Math.ceil(msin.length / 2));
  for (let i = 0; i < msin.length; i += 2) {
    packed[i / 2] = Number(msin[i]) | ((i + 1 < msin.length ? Number(msin[i + 1]) : 15) << 4);
  }
  return packed;
}

export function unpackMsin(packed: Uint8Array): string {
  if (packed.length === 0) throw new Error("Missing subscriber digits.");
  let digits = "";
  for (let i = 0; i < packed.length; i++) {
    const low = packed[i]! & 15;
    const high = packed[i]! >> 4;
    if (low > 9 || (high > 9 && (high !== 15 || i !== packed.length - 1))) {
      throw new Error("Invalid packed MSIN.");
    }
    digits += String(low);
    if (high === 15) return digits;
    digits += String(high);
  }
  return digits;
}

/** ANSI X9.63 KDF: SHA-256(Z || 32-bit big-endian counter || SharedInfo1). */
export async function deriveProfileA(shared: Uint8Array, ephemeralPublic: Uint8Array) {
  if (shared.length !== 32 || ephemeralPublic.length !== 32) throw new Error("Invalid X25519 input length.");
  const blocks: Uint8Array[] = [];
  for (let counter = 1; counter <= 2; counter++) {
    const digest = await crypto.subtle.digest(
      "SHA-256",
      webBytes(bytes(shared, new Uint8Array([0, 0, 0, counter]), ephemeralPublic)),
    );
    blocks.push(new Uint8Array(digest));
  }
  const material = bytes(...blocks);
  return {
    encryptionKey: material.slice(0, 16),
    initialCounter: material.slice(16, 32),
    macKey: material.slice(32, 64),
  };
}

async function tagCiphertext(macKey: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", webBytes(macKey), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, webBytes(ciphertext))).slice(0, 8);
}

/** Recompute an official vector's payload from its fixed X25519 shared secret. */
export async function sealWithShared(
  shared: Uint8Array,
  ephemeralPublic: Uint8Array,
  schemeInput: Uint8Array,
): Promise<ProfileAOutput> {
  const material = await deriveProfileA(shared, ephemeralPublic);
  const key = await crypto.subtle.importKey("raw", webBytes(material.encryptionKey), "AES-CTR", false, ["encrypt"]);
  // Annex C.3.4 increments the low 32 counter bits (SP 800-38A m=32).
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-CTR", counter: webBytes(material.initialCounter), length: 32 }, key, webBytes(schemeInput),
  ));
  const mac = await tagCiphertext(material.macKey, ciphertext);
  return {
    ephemeralPublic,
    ciphertext,
    mac,
    schemeOutput: bytes(ephemeralPublic, ciphertext, mac),
  };
}

export async function generateHomeNetworkKeys(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
}

export async function sealProfileA(homePublic: CryptoKey, msin: string): Promise<ProfileAOutput> {
  const ephemeral = await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
  const ephemeralPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey));
  const shared = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "X25519", public: homePublic }, ephemeral.privateKey, 256,
  ));
  return sealWithShared(shared, ephemeralPublic, packMsin(msin));
}

export async function openProfileA(homePrivate: CryptoKey, output: Uint8Array): Promise<string> {
  if (output.length < 41) throw new Error("Profile A output is too short.");
  const ephemeralPublic = output.slice(0, 32);
  const ciphertext = output.slice(32, -8);
  const receivedTag = output.slice(-8);
  const ephemeralKey = await crypto.subtle.importKey("raw", webBytes(ephemeralPublic), { name: "X25519" }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "X25519", public: ephemeralKey }, homePrivate, 256,
  ));
  const material = await deriveProfileA(shared, ephemeralPublic);
  const expectedTag = await tagCiphertext(material.macKey, ciphertext);
  let mismatch = 0;
  for (let i = 0; i < 8; i++) mismatch |= receivedTag[i]! ^ expectedTag[i]!;
  if (mismatch !== 0) throw new Error("Home network rejected the altered SUCI (MAC mismatch).");
  const key = await crypto.subtle.importKey("raw", webBytes(material.encryptionKey), "AES-CTR", false, ["decrypt"]);
  const plaintext = new Uint8Array(await crypto.subtle.decrypt(
    { name: "AES-CTR", counter: webBytes(material.initialCounter), length: 32 }, key, webBytes(ciphertext),
  ));
  return unpackMsin(plaintext);
}
