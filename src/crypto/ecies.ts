// ── ECIES P-256 (WebCrypto) ──────────────────────────────────────────
// Ephemeral ECDH + HKDF-SHA256 + AES-256-GCM

const CURVE = "P-256";
const AES_KEY_BITS = 256;
const IV_BYTES = 12;
const HKDF_INFO = new TextEncoder().encode("iron-letter-ecies-v1");
const ECIES_PUBLIC_KEY_BYTES = 65;
const ECIES_MIN_ENVELOPE_BYTES = ECIES_PUBLIC_KEY_BYTES + IV_BYTES + 16;
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

export interface EciesKeypair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

export interface EciesExported {
  publicKeyRaw: ArrayBuffer; // 65 bytes uncompressed
  publicKeyB64: string;
  privateKeyPkcs8: ArrayBuffer;
  privateKeyB64: string;
}

export interface EciesCiphertext {
  ephemeralPub: Uint8Array; // 65 bytes
  iv: Uint8Array; // 12 bytes
  ciphertext: Uint8Array; // variable
}

// ── helpers ──────────────────────────────────────────────────────────

function toBase64Url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(s: string): Uint8Array<ArrayBuffer> {
  validateBase64Url(s, "Encoded value");
  const padded = s.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes as Uint8Array<ArrayBuffer>;
}

function validateBase64Url(value: string, label: string) {
  if (!value) {
    throw new Error(`${label} is required.`);
  }
  if (!BASE64URL_RE.test(value)) {
    throw new Error(`${label} must be base64url encoded.`);
  }
}

function validateRawPublicKey(raw: Uint8Array, label: string) {
  if (raw.length !== ECIES_PUBLIC_KEY_BYTES) {
    throw new Error(`${label} must be ${ECIES_PUBLIC_KEY_BYTES} bytes.`);
  }
  if (raw[0] !== 0x04) {
    throw new Error(`${label} must be an uncompressed P-256 point.`);
  }
}

function validatePkcs8(pkcs8: Uint8Array, label: string) {
  if (pkcs8.length < 100) {
    throw new Error(`${label} is truncated or invalid.`);
  }
}

function validateEnvelope(env: EciesCiphertext) {
  validateRawPublicKey(env.ephemeralPub, "Ephemeral public key");
  if (env.iv.length !== IV_BYTES) {
    throw new Error(`ECIES IV must be ${IV_BYTES} bytes.`);
  }
  if (env.ciphertext.length < 16) {
    throw new Error("ECIES ciphertext is truncated.");
  }
}

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

// ── 1.1  Keypair generation ──────────────────────────────────────────

export async function generateKeypair(): Promise<EciesKeypair> {
  const kp = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: CURVE },
    true,
    ["deriveBits"]
  );
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

// ── 1.2 / 1.3  Key export ───────────────────────────────────────────

export async function exportKeys(kp: EciesKeypair): Promise<EciesExported> {
  const [publicKeyRaw, privateKeyPkcs8] = await Promise.all([
    crypto.subtle.exportKey("raw", kp.publicKey),
    crypto.subtle.exportKey("pkcs8", kp.privateKey),
  ]);
  return {
    publicKeyRaw,
    publicKeyB64: toBase64Url(publicKeyRaw),
    privateKeyPkcs8,
    privateKeyB64: toBase64Url(privateKeyPkcs8),
  };
}

// ── 1.4  ECDH shared secret ─────────────────────────────────────────

async function deriveSharedBits(
  privateKey: CryptoKey,
  publicKey: CryptoKey
): Promise<ArrayBuffer> {
  return crypto.subtle.deriveBits(
    { name: "ECDH", public: publicKey },
    privateKey,
    256
  );
}

// ── 1.5  HKDF key expansion ─────────────────────────────────────────

async function hkdfExpand(sharedBits: ArrayBuffer): Promise<CryptoKey> {
  const hkdfKey = await crypto.subtle.importKey(
    "raw",
    sharedBits,
    "HKDF",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: HKDF_INFO },
    hkdfKey,
    { name: "AES-GCM", length: AES_KEY_BITS },
    false,
    ["encrypt", "decrypt"]
  );
}

// ── 1.6  AES-GCM encrypt ────────────────────────────────────────────

async function aesEncrypt(
  key: CryptoKey,
  plaintext: BufferSource
): Promise<{ iv: Uint8Array; ciphertext: Uint8Array }> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  return { iv, ciphertext: new Uint8Array(ct) };
}

// ── 1.7  AES-GCM decrypt ────────────────────────────────────────────

async function aesDecrypt(
  key: CryptoKey,
  iv: Uint8Array<ArrayBuffer>,
  ciphertext: BufferSource
): Promise<Uint8Array> {
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return new Uint8Array(pt);
}

// ── Teaching visualization: ECDH convergence ────────────────────────
// Honestly demonstrates the "aha" of asymmetry: the sender computes the
// shared secret from (ephemeral private × recipient public) and the receiver
// computes it from (recipient private × ephemeral public). Both land on the
// SAME 32 bytes — that is why only the matching private key can decrypt.
// Everything here is a REAL WebCrypto ECDH/HKDF computation; nothing is faked.

export interface EcdhDemo {
  ephemeralPub: Uint8Array; // 65 bytes, the ephemeral public key that ships
  recipientPub: Uint8Array; // 65 bytes, the recipient's public key
  senderSecret: Uint8Array; // 32 bytes: ephPriv × recipientPub
  receiverSecret: Uint8Array; // 32 bytes: recipientPriv × ephPub
  aesKey: Uint8Array; // 32 bytes: HKDF(sharedSecret) → AES-256 key
  secretsMatch: boolean; // must be true; proves both sides converge
}

// Derive the AES key exactly as seal()/open() do, but export its raw bytes so
// the visualization can show the real derived key. Uses an extractable HKDF
// output ONLY for this demo path; the live seal/open path keeps it unextractable.
async function hkdfExpandExtractable(sharedBits: ArrayBuffer): Promise<Uint8Array> {
  const hkdfKey = await crypto.subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
  const aes = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: HKDF_INFO },
    hkdfKey,
    { name: "AES-GCM", length: AES_KEY_BITS },
    true,
    ["encrypt", "decrypt"]
  );
  return new Uint8Array(await crypto.subtle.exportKey("raw", aes));
}

export async function deriveEcdhDemo(recipient: EciesKeypair): Promise<EcdhDemo> {
  const eph = await generateKeypair();
  const [ephPubRaw, recipientPubRaw] = await Promise.all([
    crypto.subtle.exportKey("raw", eph.publicKey),
    crypto.subtle.exportKey("raw", recipient.publicKey),
  ]);

  // Sender side: ephemeral private × recipient public.
  const senderBits = await deriveSharedBits(eph.privateKey, recipient.publicKey);
  // Receiver side: recipient private × ephemeral public.
  const receiverBits = await deriveSharedBits(recipient.privateKey, eph.publicKey);

  const senderSecret = new Uint8Array(senderBits);
  const receiverSecret = new Uint8Array(receiverBits);
  const aesKey = await hkdfExpandExtractable(senderBits);

  let secretsMatch = senderSecret.length === receiverSecret.length;
  for (let i = 0; secretsMatch && i < senderSecret.length; i++) {
    if (senderSecret[i] !== receiverSecret[i]) secretsMatch = false;
  }

  return {
    ephemeralPub: new Uint8Array(ephPubRaw),
    recipientPub: new Uint8Array(recipientPubRaw),
    senderSecret,
    receiverSecret,
    aesKey,
    secretsMatch,
  };
}

// ── 1.8  ECIES seal ─────────────────────────────────────────────────

export async function seal(
  recipientPubKey: CryptoKey,
  plaintext: BufferSource
): Promise<EciesCiphertext> {
  // ephemeral keypair
  const eph = await generateKeypair();
  const ephPubRaw = await crypto.subtle.exportKey("raw", eph.publicKey);

  // ECDH + HKDF
  const shared = await deriveSharedBits(eph.privateKey, recipientPubKey);
  const aesKey = await hkdfExpand(shared);

  // AES-GCM
  const { iv, ciphertext } = await aesEncrypt(aesKey, plaintext);

  return {
    ephemeralPub: new Uint8Array(ephPubRaw),
    iv,
    ciphertext,
  };
}

// ── 1.9  ECIES open ─────────────────────────────────────────────────

export async function open(
  recipientPrivKey: CryptoKey,
  envelope: EciesCiphertext
): Promise<Uint8Array> {
  validateEnvelope(envelope);

  // import ephemeral public key
  const ephPub = await crypto.subtle.importKey(
    "raw",
    envelope.ephemeralPub as Uint8Array<ArrayBuffer>,
    { name: "ECDH", namedCurve: CURVE },
    false,
    []
  );

  // ECDH + HKDF
  const shared = await deriveSharedBits(recipientPrivKey, ephPub);
  const aesKey = await hkdfExpand(shared);

  // AES-GCM decrypt
  return aesDecrypt(aesKey, envelope.iv as Uint8Array<ArrayBuffer>, envelope.ciphertext as Uint8Array<ArrayBuffer>);
}

// ── Serialization ────────────────────────────────────────────────────

export function serializeEnvelope(env: EciesCiphertext): string {
  validateEnvelope(env);
  const packed = concat(env.ephemeralPub, env.iv, env.ciphertext);
  return toBase64Url(packed.buffer as ArrayBuffer);
}

export function deserializeEnvelope(s: string): EciesCiphertext {
  const data = fromBase64Url(s);
  if (data.length < ECIES_MIN_ENVELOPE_BYTES) {
    throw new Error("ECIES payload is too short.");
  }
  return {
    ephemeralPub: data.slice(0, ECIES_PUBLIC_KEY_BYTES),
    iv: data.slice(ECIES_PUBLIC_KEY_BYTES, ECIES_PUBLIC_KEY_BYTES + IV_BYTES),
    ciphertext: data.slice(ECIES_PUBLIC_KEY_BYTES + IV_BYTES),
  };
}

// ── Import keys from base64url ───────────────────────────────────────

export async function importPublicKey(b64: string): Promise<CryptoKey> {
  const raw = fromBase64Url(b64);
  validateRawPublicKey(raw, "Public key");
  return crypto.subtle.importKey(
    "raw",
    raw,
    { name: "ECDH", namedCurve: CURVE },
    true,
    []
  );
}

export async function importPrivateKey(b64: string): Promise<CryptoKey> {
  const pkcs8 = fromBase64Url(b64);
  validatePkcs8(pkcs8, "Private key");
  return crypto.subtle.importKey(
    "pkcs8",
    pkcs8,
    { name: "ECDH", namedCurve: CURVE },
    true,
    ["deriveBits"]
  );
}

export {
  ECIES_PUBLIC_KEY_BYTES,
  ECIES_MIN_ENVELOPE_BYTES,
  IV_BYTES as ECIES_IV_BYTES,
  toBase64Url,
  fromBase64Url,
};
