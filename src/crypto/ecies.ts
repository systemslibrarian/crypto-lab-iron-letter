// ── ECIES P-256 (WebCrypto) ──────────────────────────────────────────
// Ephemeral ECDH + HKDF-SHA256 + AES-256-GCM

const CURVE = "P-256";
const AES_KEY_BITS = 256;
const IV_BYTES = 12;
const HKDF_INFO = new TextEncoder().encode("iron-letter-ecies-v1");

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
  const padded = s.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes as Uint8Array<ArrayBuffer>;
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
  const packed = concat(env.ephemeralPub, env.iv, env.ciphertext);
  return toBase64Url(packed.buffer as ArrayBuffer);
}

export function deserializeEnvelope(s: string): EciesCiphertext {
  const data = fromBase64Url(s);
  return {
    ephemeralPub: data.slice(0, 65),
    iv: data.slice(65, 65 + IV_BYTES),
    ciphertext: data.slice(65 + IV_BYTES),
  };
}

// ── Import keys from base64url ───────────────────────────────────────

export async function importPublicKey(b64: string): Promise<CryptoKey> {
  const raw = fromBase64Url(b64);
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
  return crypto.subtle.importKey(
    "pkcs8",
    pkcs8,
    { name: "ECDH", namedCurve: CURVE },
    true,
    ["deriveBits"]
  );
}

export { toBase64Url, fromBase64Url };
