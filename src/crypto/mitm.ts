// ── Active man-in-the-middle against ECIES ──────────────────────────
//
// The wrong-key demo elsewhere in this app shows Eve failing PASSIVELY: she
// holds a key that cannot open a letter addressed to Bob. That is the easy
// half. The hard half is that public-key encryption on its own does not tell
// Alice WHOSE public key she just received — so an Eve who sits on the wire can
// hand Alice her own key, read everything, and re-seal to Bob. Both ends see a
// perfectly ordinary conversation.
//
// Every number below is a real WebCrypto operation on freshly generated P-256
// keys: real ECDH derivations, real AES-GCM seals and opens, real ECDSA signing
// and verification. Nothing is asserted that was not computed.

import * as ecies from "./ecies";

const IDENTITY_KEY_ALG: EcKeyGenParams = { name: "ECDSA", namedCurve: "P-256" };
const IDENTITY_SIGN_ALG: EcdsaParams = { name: "ECDSA", hash: "SHA-256" };

// What Eve substitutes for Alice's words when she chooses to rewrite rather
// than merely read. Bob's decryption of this succeeds and is indistinguishable
// to him from a genuine letter — that is the point.
export const TAMPERED_TEXT =
  "Change of plan — wire the payment to account 4471 instead. — Alice";

export interface MitmOptions {
  message: string;
  /** Does Alice verify a signature over the public key before sealing? */
  authenticated: boolean;
  /** Does Eve swap her own ECDH key in for Bob's on the wire? */
  substitute: boolean;
  /** Does Eve rewrite the message before re-sealing it to Bob? */
  tamper: boolean;
}

export interface MitmRun {
  authenticated: boolean;
  substitute: boolean;
  tamper: boolean;
  originalMessage: string;

  /** Bob's genuine ECDH public key (65 bytes). */
  bobPub: Uint8Array;
  /** The key Alice actually received over the wire. */
  offeredPub: Uint8Array;
  /** True when the offered key is not Bob's — computed by byte comparison. */
  keySubstituted: boolean;

  /** Did Alice run the signature check at all? */
  signatureChecked: boolean;
  /** Real ECDSA verify of the offered key against Bob's identity key. Always
   *  computed, so the unauthenticated run can show what Alice skipped. */
  signatureWouldVerify: boolean;
  /** Control: the same check over Bob's GENUINE signed key. Must be true. */
  genuineKeyVerifies: boolean;

  /** Alice refused to send (only possible on the authenticated path). */
  aborted: boolean;
  abortReason: string | null;

  /** ECDH secret Alice computed: ephemeral private × offered public. */
  aliceSecret: Uint8Array | null;
  /** ECDH secret Bob computes from the ephemeral key in Alice's envelope. */
  bobSecret: Uint8Array | null;
  /** Byte-comparison of the two above. */
  secretsMatch: boolean | null;

  /** Plaintext Eve actually decrypted, or null if her attempt failed/never ran. */
  eveRecovered: string | null;
  /** Plaintext Bob actually decrypted from whatever reached him. */
  bobReceived: string | null;
  /** Bob's text differs from what Alice typed. */
  bobSawAlteredText: boolean;
  /** Real attempt: can Bob open the envelope Alice produced? */
  bobCanOpenAliceEnvelope: boolean;

  aliceEnvelopeB64: string | null;
  relayedEnvelopeB64: string | null;
}

interface IdentityKeys {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

async function generateIdentity(): Promise<IdentityKeys> {
  const kp = await crypto.subtle.generateKey(IDENTITY_KEY_ALG, false, ["sign", "verify"]);
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

async function signKey(identity: IdentityKeys, rawPub: Uint8Array): Promise<Uint8Array> {
  const sig = await crypto.subtle.sign(
    IDENTITY_SIGN_ALG,
    identity.privateKey,
    rawPub as Uint8Array<ArrayBuffer>
  );
  return new Uint8Array(sig);
}

async function verifyKeySignature(
  identityPub: CryptoKey,
  sig: Uint8Array,
  rawPub: Uint8Array
): Promise<boolean> {
  return crypto.subtle.verify(
    IDENTITY_SIGN_ALG,
    identityPub,
    sig as Uint8Array<ArrayBuffer>,
    rawPub as Uint8Array<ArrayBuffer>
  );
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let equal = true;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) equal = false;
  return equal;
}

export async function runMitm(opts: MitmOptions): Promise<MitmRun> {
  const { message, authenticated, substitute, tamper } = opts;

  // Fresh keys every run: Bob and Eve each hold an ECDH keypair for sealing and
  // a long-term ECDSA identity keypair. Alice is assumed to already know Bob's
  // IDENTITY public key (out of band — that assumption is the trust anchor the
  // whole authenticated path rests on); she does not yet know his ECDH key.
  const [bobEcdh, eveEcdh, bobIdentity, eveIdentity] = await Promise.all([
    ecies.generateKeypair(),
    ecies.generateKeypair(),
    generateIdentity(),
    generateIdentity(),
  ]);

  const [bobPubBuf, evePubBuf] = await Promise.all([
    crypto.subtle.exportKey("raw", bobEcdh.publicKey),
    crypto.subtle.exportKey("raw", eveEcdh.publicKey),
  ]);
  const bobPub = new Uint8Array(bobPubBuf);
  const evePub = new Uint8Array(evePubBuf);

  // Bob signs his own ECDH key with his identity key and publishes both.
  const bobSig = await signKey(bobIdentity, bobPub);

  // On the wire, Eve either passes Bob's offer through or replaces it. She
  // cannot forge Bob's signature, so the best she can do is sign HER key with
  // HER identity key and hope nobody checks whose signature it is.
  const offeredPub = substitute ? evePub : bobPub;
  const offeredSig = substitute ? await signKey(eveIdentity, evePub) : bobSig;

  const keySubstituted = !bytesEqual(offeredPub, bobPub);

  // Both verifications are real, and both run every time: the second is the
  // control proving the check is capable of returning true.
  const [signatureWouldVerify, genuineKeyVerifies] = await Promise.all([
    verifyKeySignature(bobIdentity.publicKey, offeredSig, offeredPub),
    verifyKeySignature(bobIdentity.publicKey, bobSig, bobPub),
  ]);

  const base: MitmRun = {
    authenticated,
    substitute,
    tamper,
    originalMessage: message,
    bobPub,
    offeredPub,
    keySubstituted,
    signatureChecked: authenticated,
    signatureWouldVerify,
    genuineKeyVerifies,
    aborted: false,
    abortReason: null,
    aliceSecret: null,
    bobSecret: null,
    secretsMatch: null,
    eveRecovered: null,
    bobReceived: null,
    bobSawAlteredText: false,
    bobCanOpenAliceEnvelope: false,
    aliceEnvelopeB64: null,
    relayedEnvelopeB64: null,
  };

  if (authenticated && !signatureWouldVerify) {
    return {
      ...base,
      aborted: true,
      abortReason:
        "ECDSA verification of the offered key against Bob's identity key returned false. Alice never sealed anything, so there was nothing for Eve to read.",
    };
  }

  // Alice seals to the key she was handed, believing it is Bob's.
  const plaintext = new TextEncoder().encode(message);
  const alice = await ecies.sealTraced(await ecies.importRawPublicKey(offeredPub), plaintext);
  const aliceEnvelopeB64 = ecies.serializeEnvelope(alice.envelope);

  // What Bob computes from the ephemeral key that shipped in Alice's envelope.
  // Under substitution this is a different point multiplication entirely, so it
  // lands on different bytes than Alice's.
  const bobSecret = await ecies.deriveSecretForRawPub(
    bobEcdh.privateKey,
    alice.envelope.ephemeralPub
  );
  const secretsMatch = bytesEqual(alice.sharedSecret, bobSecret);

  // Real attempt, not an assumption: hand Bob the envelope Alice produced.
  let bobCanOpenAliceEnvelope = false;
  try {
    await ecies.open(bobEcdh.privateKey, alice.envelope);
    bobCanOpenAliceEnvelope = true;
  } catch {
    bobCanOpenAliceEnvelope = false;
  }

  // Real attempt: Eve tries her own private key against the same envelope.
  let eveRecovered: string | null = null;
  try {
    const opened = await ecies.open(eveEcdh.privateKey, alice.envelope);
    eveRecovered = new TextDecoder().decode(opened);
  } catch {
    eveRecovered = null;
  }

  // Eve relays. If she could not read it she can only forward the bytes, which
  // Bob then cannot open; if she could, she re-seals to Bob's genuine key —
  // optionally with her own words in place of Alice's.
  let relayedEnvelopeB64: string | null = null;
  let bobReceived: string | null = null;
  if (eveRecovered !== null) {
    const relayText = tamper ? TAMPERED_TEXT : eveRecovered;
    const relayed = await ecies.seal(bobEcdh.publicKey, new TextEncoder().encode(relayText));
    relayedEnvelopeB64 = ecies.serializeEnvelope(relayed);
    const opened = await ecies.open(bobEcdh.privateKey, relayed);
    bobReceived = new TextDecoder().decode(opened);
  } else if (bobCanOpenAliceEnvelope) {
    relayedEnvelopeB64 = aliceEnvelopeB64;
    const opened = await ecies.open(bobEcdh.privateKey, alice.envelope);
    bobReceived = new TextDecoder().decode(opened);
  }

  return {
    ...base,
    aliceSecret: alice.sharedSecret,
    bobSecret,
    secretsMatch,
    eveRecovered,
    bobReceived,
    bobSawAlteredText: bobReceived !== null && bobReceived !== message,
    bobCanOpenAliceEnvelope,
    aliceEnvelopeB64,
    relayedEnvelopeB64,
  };
}
