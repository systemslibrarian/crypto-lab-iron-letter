// ── Iron Letter — Main Entry ─────────────────────────────────────────

import "./style.css";
import * as ecies from "./crypto/ecies";
import * as rsa from "./crypto/rsa";
import type { EcdhDemo } from "./crypto/ecies";
import { measure, measureAverage, emptyMetrics, type Metrics } from "./crypto/metrics";
import { runStartupSelfTest } from "./crypto/selftest";
import { buildShareUrl, parseCurrentUrl } from "./keyurl";
import { generateQrSvg } from "./qr";

// ── Boot self-test ───────────────────────────────────────────────────

function checkWebCrypto(): boolean {
  return (
    typeof crypto !== "undefined" &&
    typeof crypto.subtle !== "undefined" &&
    typeof crypto.subtle.generateKey === "function"
  );
}

// ── State ────────────────────────────────────────────────────────────

// Two-party ("Alice → Bob") model. Each party gets its OWN keypair so a
// learner encrypts to SOMEONE ELSE's public key — the whole point of asymmetry.
// `bob` is the recipient (his public key is the seal default, his private key
// opens the letter). `eve` is an eavesdropper whose private key is offered as a
// one-click "wrong key" so decryption visibly fails with a GCM auth error.
interface Party {
  publicKey: CryptoKey | null;
  privateKey: CryptoKey | null;
  publicKeyB64: string;
  privateKeyB64: string;
}

interface AlgoState {
  // "You"/Alice keep the historical field names for backward compatibility
  // (deep links, share URLs, self-test all reference these).
  publicKey: CryptoKey | null;
  privateKey: CryptoKey | null;
  publicKeyB64: string;
  privateKeyB64: string;
  bob: Party; // the recipient
  eve: Party; // the eavesdropper (wrong key for the failure demo)
  ciphertext: string;
  metrics: Metrics;
  sealStatus: { kind: "ok" | "error"; text: string } | null;
  ecdhDemo: EcdhDemo | null; // ECIES convergence panel
  recipientB64: string; // recipient public key from a deep link; persists across re-renders
}

function emptyParty(): Party {
  return { publicKey: null, privateKey: null, publicKeyB64: "", privateKeyB64: "" };
}

type Tab = "ecies" | "rsa2048" | "rsa4096" | "compare";
type SelfTestState =
  | { status: "running"; message: string }
  | { status: "passed"; message: string }
  | { status: "failed"; message: string };

let currentTab: Tab = "ecies";
let selfTestState: SelfTestState = {
  status: "running",
  message: "Running WebCrypto self-check...",
};
let globalListenersBound = false;
type Theme = "dark" | "light";
let copyUrlTimerId: ReturnType<typeof setTimeout> | null = null;
const qrVisible: Record<"ecies" | "rsa2048" | "rsa4096", boolean> = { ecies: false, rsa2048: false, rsa4096: false };

function emptyAlgoState(): AlgoState {
  return {
    publicKey: null, privateKey: null, publicKeyB64: "", privateKeyB64: "",
    bob: emptyParty(), eve: emptyParty(),
    ciphertext: "", metrics: emptyMetrics(), sealStatus: null, ecdhDemo: null, recipientB64: "",
  };
}

const state: Record<"ecies" | "rsa2048" | "rsa4096", AlgoState> = {
  ecies: emptyAlgoState(),
  rsa2048: emptyAlgoState(),
  rsa4096: emptyAlgoState(),
};

// Number of iterations the Compare benchmark averages encrypt/decrypt over.
const BENCH_ITERATIONS = 25;
const BENCH_MESSAGE = new TextEncoder().encode(
  "Iron Letter benchmark — the quick brown fox jumps over the lazy dog."
);
// Approximate symmetric-equivalent security per NIST SP 800-57. The teaching
// point: RSA-2048's much larger key is actually *weaker* than P-256.
const SECURITY_BITS: Record<"ecies" | "rsa2048" | "rsa4096", number> = {
  ecies: 128,
  rsa2048: 112,
  rsa4096: 140,
};
let benchmarkRunning = false;

// ── UI Rendering ─────────────────────────────────────────────────────

const app = document.getElementById("app")!;

function getCurrentTheme(): Theme {
  return document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
}

function getThemeButtonState(theme: Theme): { icon: string; ariaLabel: string } {
  if (theme === "dark") {
    return { icon: "🌙", ariaLabel: "Switch to light mode" };
  }
  return { icon: "☀️", ariaLabel: "Switch to dark mode" };
}

function applyTheme(theme: Theme) {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem("theme", theme);
  const btn = document.getElementById("btn-theme") as HTMLButtonElement | null;
  if (!btn) return;
  const next = getThemeButtonState(theme);
  btn.textContent = next.icon;
  btn.setAttribute("aria-label", next.ariaLabel);
}

function render() {
  const themeState = getThemeButtonState(getCurrentTheme());
  app.innerHTML = `
    <div class="max-w-4xl mx-auto px-4 py-8">
      <button
        id="btn-theme"
        type="button"
        class="theme-toggle"
        aria-label="${themeState.ariaLabel}"
      >${themeState.icon}</button>
      <header class="cl-hero">
        <div class="cl-hero-main">
          <h1 class="cl-hero-title text-zinc-100"><span class="text-amber-400">⛒</span> Iron Letter</h1>
          <p class="cl-hero-sub text-zinc-400">ECIES P-256 · RSA-OAEP hybrid public-key encryption</p>
        </div>
        <aside class="cl-hero-why" aria-label="Why it matters">
          <span class="cl-hero-why-label text-amber-400">WHY IT MATTERS</span>
          <p class="cl-hero-why-text text-zinc-300">Seal a message to someone's public key and only their private key can open it. This compares two ways to do it — ECIES (ECDH + HKDF + AES-GCM) and RSA-OAEP — showing how ECC matches RSA's security with far smaller keys.</p>
        </aside>
      </header>

      ${renderSelfTest()}

      <nav class="flex flex-wrap gap-1 mb-6 border-b border-zinc-800" role="tablist" aria-label="Encryption algorithms">
        ${renderTab("ecies", "ECIES P-256")}
        ${renderTab("rsa2048", "RSA-2048")}
        ${renderTab("rsa4096", "RSA-4096")}
        ${renderTab("compare", "Compare")}
      </nav>

      <main id="main-content" role="tabpanel" aria-labelledby="tab-${currentTab}">
        ${currentTab === "compare" ? renderCompare() : renderAlgoPanel(currentTab)}
      </main>

      <div aria-live="polite" aria-atomic="true" id="status-announcer" class="sr-only"></div>

      <footer class="mt-12 pt-6 border-t border-zinc-800 text-center">
        <button id="btn-how" class="text-xs text-zinc-400 hover:text-zinc-300 underline underline-offset-4 transition-colors">
          How It Works
        </button>
        <p class="text-xs text-zinc-400 mt-2">
          All cryptography runs locally via WebCrypto. Private keys never leave your browser.
        </p>
        <p class="text-xs text-zinc-400 mt-2">
          Related demos:
          <a href="https://systemslibrarian.github.io/crypto-lab-rsa-forge/" target="_blank" rel="noreferrer" class="underline underline-offset-4 hover:text-zinc-300 transition-colors">crypto-lab-rsa-forge</a> ·
          <a href="https://systemslibrarian.github.io/crypto-lab-envelope-kms/" target="_blank" rel="noreferrer" class="underline underline-offset-4 hover:text-zinc-300 transition-colors">crypto-lab-envelope-kms</a> ·
          <a href="https://systemslibrarian.github.io/crypto-lab-ibe-gate/" target="_blank" rel="noreferrer" class="underline underline-offset-4 hover:text-zinc-300 transition-colors">crypto-lab-ibe-gate</a> ·
          <a href="https://systemslibrarian.github.io/crypto-lab-elgamal-plain/" target="_blank" rel="noreferrer" class="underline underline-offset-4 hover:text-zinc-300 transition-colors">crypto-lab-elgamal-plain</a> ·
          <a href="https://systemslibrarian.github.io/crypto-lab-curve-lens/" target="_blank" rel="noreferrer" class="underline underline-offset-4 hover:text-zinc-300 transition-colors">crypto-lab-curve-lens</a>
        </p>
        <p class="text-zinc-400" style="font-size: 0.85rem; margin-top: 1.5rem;">
          Whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31
        </p>
      </footer>
    </div>

    ${renderHowItWorksModal()}
  `;

  bindEvents();
}

function renderSelfTest(): string {
  if (!checkWebCrypto()) {
    return `<div class="text-sm text-red-400 text-center mb-4 p-3 border border-red-800 rounded-lg bg-red-950" role="alert">
    WebCrypto unavailable. This app requires a secure context (HTTPS or localhost).
  </div>`;
  }

  if (selfTestState.status === "running") {
    return `<div class="text-xs text-amber-400 text-center mb-4" role="status">${selfTestState.message}</div>`;
  }

  if (selfTestState.status === "passed") {
    return `<div class="text-xs text-emerald-500 text-center mb-4" role="status">${selfTestState.message}</div>`;
  }

  return `<div class="text-sm text-red-400 text-center mb-4 p-3 border border-red-800 rounded-lg bg-red-950" role="alert">
    ${escapeHtml(selfTestState.message)}
  </div>`;
}

function renderTab(id: Tab, label: string): string {
  const active = currentTab === id;
  return `<button
    id="tab-${id}"
    data-tab="${id}"
    role="tab"
    aria-selected="${active}"
    aria-controls="main-content"
    tabindex="${active ? "0" : "-1"}"
    class="min-h-[44px] px-4 py-2 text-sm font-medium transition-colors ${
      active
        ? "text-amber-400 border-b-2 border-amber-400 -mb-px"
        : "text-zinc-400 hover:text-zinc-200"
    }"
  >${label}</button>`;
}

// ── Teaching helpers: glossary, hex, byte-layout strip ───────────────

// Inline glossary: dotted-underline term with an accessible <abbr>-style
// tooltip. `title` gives the native hover/focus tooltip and aria-label gives
// screen-reader users the same definition. Kept short so newcomers get an
// on-ramp for jargon without leaving the page.
const GLOSSARY: Record<string, string> = {
  ECIES:
    "Elliptic Curve Integrated Encryption Scheme: a standard hybrid recipe combining ECDH + a KDF + a symmetric cipher.",
  ECDH:
    "Elliptic-Curve Diffie–Hellman: mixes one side's private key with the other side's public key. Both parties independently arrive at the SAME shared secret.",
  HKDF:
    "HMAC-based Key Derivation Function: stretches/cleans a raw shared secret into a uniformly-random symmetric key of the size you need.",
  ephemeral:
    "A throwaway keypair generated fresh for a single message and discarded. Only its public half ships inside the envelope; its private half is destroyed.",
  OAEP:
    "Optimal Asymmetric Encryption Padding: the randomized padding that makes RSA encryption safe (never encrypt raw RSA without it).",
  SPKI:
    "SubjectPublicKeyInfo: the standard DER byte format WebCrypto exports a public key in.",
  PKCS8:
    "PKCS#8: the standard DER byte format WebCrypto exports a private key in.",
  "AES-GCM":
    "AES in Galois/Counter Mode: authenticated encryption. The 16-byte tag verifies integrity — decryption with the wrong key fails loudly instead of returning garbage.",
  "symmetric-equivalent bits":
    "How many bits of a symmetric key (like AES) would give the same brute-force resistance. 128-bit ≈ 3.4×10^38 operations. It lets you compare RSA and ECC key strength on one scale.",
  base64url:
    "URL-safe Base64 text encoding of raw bytes (uses - and _ instead of + and /, no padding). Just a way to print binary keys/ciphertext as ASCII.",
};

function glossaryId(term: string): string {
  return "gloss-" + term.replace(/[^A-Za-z0-9]/g, "-").toLowerCase();
}

// Renders a dotted-underline term whose definition is available on hover
// (title) and to assistive tech (aria-describedby → a visually-hidden node).
function term(t: string, display?: string): string {
  const def = GLOSSARY[t];
  const label = display ?? t;
  if (!def) return escapeHtml(label);
  const id = glossaryId(t);
  return `<span class="gloss-term" tabindex="0" role="note" title="${escapeHtml(def)}" aria-describedby="${id}">${escapeHtml(label)}<span id="${id}" class="sr-only">${escapeHtml(def)}</span></span>`;
}

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

// A labelled, color-coded byte-layout strip mapping the envelope structure onto
// the REAL byte counts. Widths are proportional to segment size, so the RSA
// wrapped-key segment visibly dominates while ECIES's ephemeral-key segment is
// tiny — the concrete embodiment of "hybrid encryption".
interface ByteSeg {
  label: string;
  bytes: number;
  cls: string; // background utility class (has AA-contrast dark text)
  desc: string; // tooltip
}

function renderByteStrip(segs: ByteSeg[], caption: string): string {
  const total = segs.reduce((n, s) => n + s.bytes, 0) || 1;
  const bars = segs
    .map((seg) => {
      const pct = Math.max((seg.bytes / total) * 100, 6); // floor so tiny segs stay visible
      return `<div class="byte-seg ${seg.cls}" style="flex:0 0 ${pct}%" title="${escapeHtml(seg.desc)}">
        <span class="byte-seg-label">${escapeHtml(seg.label)}</span>
        <span class="byte-seg-bytes">${seg.bytes} B</span>
      </div>`;
    })
    .join("");
  const legend = segs
    .map(
      (seg) =>
        `<li class="flex items-center gap-1.5"><span class="byte-swatch ${seg.cls}" aria-hidden="true"></span>${escapeHtml(seg.label)} — ${seg.bytes} bytes</li>`
    )
    .join("");
  return `
    <div class="mt-3" role="group" aria-label="${escapeHtml(caption)}">
      <div class="byte-strip flex w-full rounded-lg overflow-hidden border border-zinc-700" aria-hidden="true">${bars}</div>
      <ul class="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-zinc-400">${legend}</ul>
    </div>`;
}

function renderCiphertextLayout(algo: "ecies" | "rsa2048" | "rsa4096"): string {
  const s = state[algo];
  if (!s.ciphertext) return "";
  if (algo === "ecies") {
    const env = ecies.deserializeEnvelope(s.ciphertext);
    return renderByteStrip(
      [
        { label: "Ephemeral public key", bytes: env.ephemeralPub.length, cls: "seg-eph", desc: "The sender's throwaway (ephemeral) P-256 public key, 65 bytes. The recipient combines it with their private key to re-derive the shared secret." },
        { label: "IV / nonce", bytes: env.iv.length, cls: "seg-iv", desc: "The 12-byte AES-GCM initialization vector (nonce). Random per message; not secret." },
        { label: "Ciphertext + tag", bytes: env.ciphertext.length, cls: "seg-ct", desc: "The AES-256-GCM encrypted message plus its 16-byte authentication tag." },
      ],
      "ECIES envelope byte layout: ephemeral public key, IV, ciphertext and tag"
    );
  }
  const keySize = algo === "rsa2048" ? 2048 : 4096;
  const env = rsa.deserializeEnvelope(s.ciphertext, keySize as rsa.RsaKeySize);
  return renderByteStrip(
    [
      { label: "Wrapped AES key", bytes: env.wrappedKey.length, cls: "seg-eph", desc: `The random AES-256 key, RSA-OAEP-encrypted to the recipient. Its size equals the RSA modulus: ${keySize / 8} bytes. This is why RSA ciphertext carries a big fixed overhead.` },
      { label: "IV / nonce", bytes: env.iv.length, cls: "seg-iv", desc: "The 12-byte AES-GCM initialization vector (nonce). Random per message; not secret." },
      { label: "Ciphertext + tag", bytes: env.ciphertext.length, cls: "seg-ct", desc: "The AES-256-GCM encrypted message plus its 16-byte authentication tag." },
    ],
    "RSA hybrid envelope byte layout: wrapped AES key, IV, ciphertext and tag"
  );
}

// The ECDH convergence panel — the "aha" of asymmetry made observable.
// Shows the sender computing (ephemeral private × Bob public) and the receiver
// computing (Bob private × ephemeral public), both landing on the SAME 32-byte
// secret, which then flows through HKDF into the AES key. All bytes are REAL.
function renderEcdhPanel(algo: "ecies" | "rsa2048" | "rsa4096"): string {
  if (algo !== "ecies") return "";
  const demo = state.ecies.ecdhDemo;
  if (!demo) return "";
  const senderHex = toHex(demo.senderSecret);
  const receiverHex = toHex(demo.receiverSecret);
  // Highlight the shared secret as fixed-width hex so a learner can eyeball that
  // both columns are byte-for-byte identical. `.ecdh-*` classes carry their own
  // theme-safe colors (they don't rely on Tailwind zinc classes that flip).
  const secretRow = (hex: string, label: string) =>
    `<div class="ecdh-secret" tabindex="0" role="region" aria-label="${label}">${hex.replace(/(.{2})/g, '<span class="ecdh-byte">$1</span>')}</div>`;

  return `
    <section class="bg-zinc-900 rounded-xl p-6 border border-zinc-800">
      <h2 class="text-lg font-semibold text-zinc-200 mb-1"><span aria-hidden="true">🤝</span> Why only Bob can open it: the ${term("ECDH")} handshake</h2>
      <p class="text-xs text-zinc-400 mb-4">
        Both sides run ${term("ECDH")} but start from different halves — yet they compute the
        <em>identical</em> 32-byte secret. That is the whole trick: the secret is never sent, only re-derived,
        and only Bob's private key can re-derive it.
      </p>
      <div class="grid md:grid-cols-2 gap-4">
        <div class="ecdh-card ecdh-alice">
          <h3 class="ecdh-card-title ecdh-alice-title">Alice (sender) computes</h3>
          <p class="ecdh-formula">
            <span class="ecdh-eph">${term("ephemeral", "ephemeral")} private</span>
            <span aria-hidden="true">×</span><span class="sr-only">times</span>
            <span class="ecdh-recip">Bob public</span>
          </p>
          ${secretRow(senderHex, "Shared secret Alice derived, 32 bytes as hex")}
        </div>
        <div class="ecdh-card ecdh-bob">
          <h3 class="ecdh-card-title ecdh-bob-title">Bob (recipient) computes</h3>
          <p class="ecdh-formula">
            <span class="ecdh-recip">Bob private</span>
            <span aria-hidden="true">×</span><span class="sr-only">times</span>
            <span class="ecdh-eph">ephemeral public</span>
          </p>
          ${secretRow(receiverHex, "Shared secret Bob derived, 32 bytes as hex")}
        </div>
      </div>
      <div class="text-center my-3" aria-hidden="true">
        <span class="ecdh-arrow">↓</span>
      </div>
      <div class="ecdh-result ${demo.secretsMatch ? "ecdh-result-ok" : "ecdh-result-bad"}">
        <p class="ecdh-result-head">
          ${demo.secretsMatch ? "✓ Both sides derived the SAME 32 bytes" : "✗ Secrets differ (unexpected!)"}
        </p>
        <p class="text-xs text-zinc-400 mt-1">
          This shared secret feeds ${term("HKDF")} → a 256-bit AES key:
        </p>
        <div class="ecdh-aeskey" tabindex="0" role="region" aria-label="AES-256 key derived by HKDF from the shared secret">${toHex(demo.aesKey)}</div>
      </div>
      <p class="text-xs text-zinc-400 mt-3">
        These are real WebCrypto ECDH derivations for this session's keys — recompute them by generating a new keypair.
        The live seal/open path keeps the derived key unextractable; it is exported here only to visualize it.
      </p>
    </section>
  `;
}

function renderAlgoPanel(algo: "ecies" | "rsa2048" | "rsa4096"): string {
  const s = state[algo];
  const m = s.metrics;
  // TWO-PARTY DEFAULT: seal to BOB (someone else), not yourself. A deep-linked
  // recipient key still takes precedence (share-URL flow). Falling back to Bob's
  // key — never your own — forces the learner to grapple with "I encrypt to
  // SOMEONE ELSE's public key", which is the entire meaning of asymmetry.
  const recipientPublicKey = s.recipientB64 || s.bob.publicKeyB64;
  const algoLabel =
    algo === "ecies" ? "ECIES P-256" : algo === "rsa2048" ? "RSA-2048" : "RSA-4096";

  return `
    <div class="space-y-6">
      <!-- Two-party primer -->
      <section class="bg-zinc-900 rounded-xl p-5 border border-zinc-800">
        <p class="text-sm text-zinc-300">
          <span class="font-semibold text-sky-300">Alice</span> wants to send a private letter to
          <span class="font-semibold text-emerald-300">Bob</span>. She seals it with
          <span class="text-emerald-300">Bob's <em>public</em> key</span> — which anyone may know — and only
          <span class="text-emerald-300">Bob's <em>private</em> key</span> can open it. Not even Alice can re-open it.
          <span class="text-violet-300">Eve</span> the eavesdropper holds a different keypair, and you can watch her fail.
        </p>
        <p class="text-xs text-zinc-400 mt-2">
          That directional asymmetry — encrypt with one key, decrypt only with its partner — is the whole idea.
          Generate keys below to give each party a real ${algoLabel} keypair.
        </p>
      </section>

      <!-- Keygen Panel -->
      <section class="bg-zinc-900 rounded-xl p-6 border border-zinc-800">
        <h2 class="text-lg font-semibold text-zinc-200 mb-4"><span aria-hidden="true">🔑</span> Key Generation</h2>
        <button id="btn-keygen" class="min-h-[44px] px-4 py-2 rounded-lg bg-amber-500 text-zinc-950 font-medium text-sm hover:bg-amber-400 transition-colors focus:outline-2 focus:outline-amber-400 focus:outline-offset-2">
          Generate ${algoLabel} keypairs for Alice, Bob & Eve
        </button>
        ${
          s.publicKeyB64
            ? `
          <div class="mt-4 space-y-3">
            <div>
              <label class="text-xs text-zinc-400 block mb-1"><span class="text-emerald-300 font-semibold">Bob's</span> Public Key (${m.publicKeySizeBytes} bytes, ${algo === "ecies" ? term("SPKI", "uncompressed point") : term("SPKI")}) — the seal target</label>
              <div class="font-mono text-xs text-emerald-400 bg-zinc-950 p-3 rounded-lg break-all max-h-24 overflow-y-auto" tabindex="0" role="region" aria-label="Bob's public key value">${escapeHtml(s.bob.publicKeyB64)}</div>
            </div>
            <div>
              <label class="text-xs text-zinc-400 block mb-1"><span class="text-sky-300 font-semibold">Alice's</span> Public Key (${m.publicKeySizeBytes} bytes) — ${m.keygenTimeMs.toFixed(1)}ms keygen</label>
              <div class="font-mono text-xs text-emerald-400 bg-zinc-950 p-3 rounded-lg break-all max-h-24 overflow-y-auto" tabindex="0" role="region" aria-label="Alice's public key value">${escapeHtml(s.publicKeyB64)}</div>
            </div>
            <div>
              <label class="text-xs text-zinc-400 block mb-1"><span class="text-sky-300 font-semibold">Alice's</span> Private Key (${m.privateKeySizeBytes} bytes, ${term("PKCS8")})</label>
              <details>
                <summary class="text-xs text-zinc-400 cursor-pointer hover:text-zinc-300">Reveal private key</summary>
                <div class="font-mono text-xs text-red-400 bg-zinc-950 p-3 rounded-lg break-all mt-1 max-h-24 overflow-y-auto" tabindex="0" role="region" aria-label="Alice's private key value">${escapeHtml(s.privateKeyB64)}</div>
              </details>
            </div>
            <!-- Share URL -->
            <div class="flex gap-2 items-center">
              <button id="btn-copy-url" class="min-h-[44px] min-w-[44px] px-3 py-2 text-xs rounded-lg bg-zinc-800 text-zinc-300 hover:bg-zinc-700 transition-colors focus:outline-2 focus:outline-amber-400 focus:outline-offset-2">
                <span aria-hidden="true">📋</span> Copy share URL
              </button>
              <button id="btn-qr" class="min-h-[44px] min-w-[44px] px-3 py-2 text-xs rounded-lg bg-zinc-800 text-zinc-300 hover:bg-zinc-700 transition-colors focus:outline-2 focus:outline-amber-400 focus:outline-offset-2">
                <span aria-hidden="true">📱</span> QR Code
              </button>
            </div>
            <div id="qr-container" class="${qrVisible[algo] ? '' : 'hidden'} mt-2"></div>
          </div>
        `
            : ""
        }
      </section>

      <!-- Seal Panel -->
      <section class="bg-zinc-900 rounded-xl p-6 border border-zinc-800">
        <h2 class="text-lg font-semibold text-zinc-200 mb-1"><span aria-hidden="true">📨</span> Seal (Encrypt) — Alice → Bob</h2>
        <p class="text-xs text-zinc-400 mb-4">Alice encrypts to <span class="text-emerald-300 font-semibold">Bob's public key</span> (pre-filled below). She could not decrypt the result herself.</p>
        <div class="space-y-3">
          <div>
            <label for="seal-recipient-pk" class="text-xs text-zinc-400 block mb-1">Recipient Public Key — <span class="text-emerald-300 font-semibold">Bob</span> (${term("base64url", "base64url")})</label>
            <input id="seal-recipient-pk" type="text" value="${escapeHtml(recipientPublicKey)}"
              class="w-full bg-zinc-950 border border-zinc-700 text-zinc-200 text-xs font-mono rounded-lg p-3 focus:outline-2 focus:outline-amber-400 focus:border-amber-400"
              placeholder="Paste recipient's public key..."
            />
          </div>
          <div>
            <label for="seal-message" class="text-xs text-zinc-400 block mb-1">Message</label>
            <textarea id="seal-message" rows="3"
              class="w-full bg-zinc-950 border border-zinc-700 text-zinc-200 text-sm rounded-lg p-3 focus:outline-2 focus:outline-amber-400 focus:border-amber-400 resize-y"
              placeholder="Type your secret message..."
            ></textarea>
          </div>
          <button id="btn-seal" class="min-h-[44px] px-4 py-2 rounded-lg bg-emerald-700 text-white font-medium text-sm hover:bg-emerald-600 transition-colors focus:outline-2 focus:outline-emerald-400 focus:outline-offset-2">
            Seal Letter
          </button>
          ${
            s.sealStatus?.kind === "error"
              ? `<div class="text-xs text-red-400 bg-zinc-950 p-3 rounded-lg border border-red-800" role="alert">${escapeHtml(s.sealStatus.text)}</div>`
              : ""
          }
          ${
            s.ciphertext
              ? `
            <div class="mt-3">
              <div class="flex items-center justify-between mb-1">
                <label class="text-xs text-zinc-400">Sealed envelope (${m.ciphertextSizeBytes} bytes) — ${m.encryptTimeMs.toFixed(1)}ms</label>
                <button id="btn-copy-ct" aria-label="Copy ciphertext to clipboard" class="min-h-[44px] min-w-[44px] px-3 py-2 text-xs rounded-lg bg-zinc-800 text-zinc-300 hover:bg-zinc-700 transition-colors focus:outline-2 focus:outline-amber-400 focus:outline-offset-2">
                  <span aria-hidden="true">📋</span> Copy
                </button>
              </div>
              <p class="text-xs text-zinc-400 mb-1">What is actually inside a sealed letter — mapped onto the real bytes:</p>
              ${renderCiphertextLayout(algo)}
              <div class="mt-2 font-mono text-xs text-sky-400 bg-zinc-950 p-3 rounded-lg break-all max-h-32 overflow-y-auto" tabindex="0" role="region" aria-label="Encrypted ciphertext as base64url">${escapeHtml(s.ciphertext)}</div>
            </div>
          `
              : ""
          }
        </div>
      </section>

      ${renderEcdhPanel(algo)}

      <!-- Open Panel -->
      <section class="bg-zinc-900 rounded-xl p-6 border border-zinc-800">
        <h2 class="text-lg font-semibold text-zinc-200 mb-1"><span aria-hidden="true">📬</span> Open (Decrypt) — Bob's private key</h2>
        <p class="text-xs text-zinc-400 mb-4">The field is pre-filled with <span class="text-emerald-300 font-semibold">Bob's</span> private key, the one the letter was sealed to. Open it, then try Eve's key to feel the boundary.</p>
        <div class="space-y-3">
          <div>
            <label for="open-privkey" class="text-xs text-zinc-400 block mb-1">Private Key — <span class="text-emerald-300 font-semibold">Bob</span> (${term("PKCS8")}, ${term("base64url", "base64url")})</label>
            <input id="open-privkey" type="text" value="${escapeHtml(s.bob.privateKeyB64)}"
              class="w-full bg-zinc-950 border border-zinc-700 text-zinc-200 text-xs font-mono rounded-lg p-3 focus:outline-2 focus:outline-amber-400 focus:border-amber-400"
              placeholder="Paste your private key..."
            />
          </div>
          <div>
            <label for="open-ciphertext" class="text-xs text-zinc-400 block mb-1">Ciphertext</label>
            <textarea id="open-ciphertext" rows="3"
              class="w-full bg-zinc-950 border border-zinc-700 text-zinc-200 text-sm font-mono rounded-lg p-3 focus:outline-2 focus:outline-amber-400 focus:border-amber-400 resize-y"
              placeholder="Paste ciphertext here..."
            >${escapeHtml(s.ciphertext)}</textarea>
          </div>
          <div class="flex flex-wrap gap-2">
            <button id="btn-open" class="min-h-[44px] px-4 py-2 rounded-lg bg-violet-600 text-white font-medium text-sm hover:bg-violet-500 transition-colors focus:outline-2 focus:outline-violet-400 focus:outline-offset-2">
              Open with Bob's key
            </button>
            ${
              s.eve.privateKeyB64 && s.ciphertext
                ? `<button id="btn-open-wrong" class="min-h-[44px] px-4 py-2 rounded-lg bg-zinc-800 text-red-300 font-medium text-sm border border-red-800 hover:bg-zinc-700 transition-colors focus:outline-2 focus:outline-red-400 focus:outline-offset-2">
                     Try opening with Eve's WRONG key
                   </button>`
                : ""
            }
          </div>
          ${
            s.eve.privateKeyB64 && s.ciphertext
              ? `<p class="text-xs text-zinc-400">The wrong-key attempt runs a real ${term("AES-GCM")} decrypt. When the ${term("ECDH")} secret does not match, the authentication tag fails and decryption is rejected — no plaintext leaks.</p>`
              : ""
          }
          <div id="open-result" class="hidden mt-3" aria-live="polite">
            <label class="text-xs text-zinc-400 block mb-1">Decrypted Message</label>
            <div id="open-plaintext" class="text-sm text-zinc-100 bg-zinc-950 p-3 rounded-lg border border-emerald-800"></div>
          </div>
        </div>
      </section>
    </div>
  `;
}

function renderCompare(): string {
  const algos: ("ecies" | "rsa2048" | "rsa4096")[] = ["ecies", "rsa2048", "rsa4096"];
  const labels = { ecies: "ECIES P-256", rsa2048: "RSA-2048", rsa4096: "RSA-4096" };

  const hasData = algos.some((a) => state[a].publicKeyB64);

  return `
    <section class="bg-zinc-900 rounded-xl p-6 border border-zinc-800">
      <div class="flex flex-wrap items-center justify-between gap-3 mb-4">
        <h2 class="text-lg font-semibold text-zinc-200"><span aria-hidden="true">📊</span> Side-by-Side Comparison</h2>
        <button id="btn-benchmark" ${benchmarkRunning ? "disabled" : ""}
          class="min-h-[44px] px-4 py-2 rounded-lg bg-amber-500 text-zinc-950 font-medium text-sm hover:bg-amber-400 transition-colors focus:outline-2 focus:outline-amber-400 focus:outline-offset-2">
          ${benchmarkRunning ? `<span class="spinner" aria-hidden="true"></span> Benchmarking…` : "⏱ Run Benchmark"}
        </button>
      </div>
      <p class="text-xs text-zinc-400 mb-4">
        One click generates a keypair for each algorithm and averages encrypt/decrypt over ${BENCH_ITERATIONS} runs — no manual setup needed.
      </p>
      ${
        !hasData
          ? `<p class="text-sm text-zinc-400">Run the benchmark above, or generate keys and encrypt messages in each tab, to see comparisons.</p>`
          : `
        <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead>
              <tr class="text-zinc-400 text-xs text-left border-b border-zinc-800">
                <th class="py-2 pr-4">Metric</th>
                ${algos.map((a) => `<th class="py-2 px-4">${labels[a]}</th>`).join("")}
              </tr>
            </thead>
            <tbody class="text-zinc-300">
              ${compareRow("Security level", algos.map((a) => `~${SECURITY_BITS[a]}-bit`))}
              ${compareRow("Keygen time", algos.map((a) => fmtMs(state[a].metrics.keygenTimeMs)))}
              ${compareRow("Public key size", algos.map((a) => fmtBytes(state[a].metrics.publicKeySizeBytes)))}
              ${compareRow("Private key size", algos.map((a) => fmtBytes(state[a].metrics.privateKeySizeBytes)))}
              ${compareRow("Encrypt time", algos.map((a) => fmtMs(state[a].metrics.encryptTimeMs)))}
              ${compareRow("Ciphertext size", algos.map((a) => fmtBytes(state[a].metrics.ciphertextSizeBytes)))}
              ${compareRow("Decrypt time", algos.map((a) => fmtMs(state[a].metrics.decryptTimeMs)))}
            </tbody>
          </table>
        </div>
        <p class="text-xs text-zinc-400 mt-3">
          "Security level" is the approximate ${term("symmetric-equivalent bits", "symmetric-equivalent bits")} of strength
          (NIST SP 800-57): how big an AES key would resist brute force equally hard. Higher is stronger; each extra bit
          <em>doubles</em> the attacker's work.
        </p>
        <p class="text-xs text-zinc-300 mt-2 p-3 rounded-lg border border-amber-800 bg-zinc-950">
          <strong class="text-amber-300">The counterintuitive takeaway:</strong> RSA-2048's far larger key (${fmtBytes(state.rsa2048.metrics.publicKeySizeBytes)})
          is actually <em>weaker</em> (~112-bit) than ECIES P-256's 65-byte key (~128-bit). RSA's security grows only very
          slowly with key size, so bigger RSA keys buy <em>less security per byte</em> than ECC — that is why modern systems
          reach for elliptic curves.
        </p>

        <!-- Key size visual bar chart -->
        <div class="mt-6">
          <h3 class="text-sm font-medium text-zinc-400 mb-3">Public Key Size Comparison</h3>
          <div class="space-y-2">
            ${algos
              .map((a) => {
                const bytes = state[a].metrics.publicKeySizeBytes;
                const max = Math.max(...algos.map((x) => state[x].metrics.publicKeySizeBytes), 1);
                const pct = (bytes / max) * 100;
                return `
                  <div class="flex items-center gap-3" role="img" aria-label="${labels[a]}: ${bytes} bytes">
                    <span class="text-xs text-zinc-400 w-20 shrink-0">${labels[a]}</span>
                    <div class="flex-1 bg-zinc-800 rounded-full h-4 overflow-hidden">
                      <div class="h-full bg-amber-500 rounded-full transition-all" style="width: ${pct}%"></div>
                    </div>
                    <span class="text-xs text-zinc-400 w-20 text-right">${bytes} B</span>
                  </div>
                `;
              })
              .join("")}
          </div>
        </div>
      `
      }
    </section>
  `;
}

function compareRow(label: string, values: string[]): string {
  return `<tr class="border-b border-zinc-800/50">
    <td class="py-2 pr-4 text-zinc-400">${label}</td>
    ${values.map((v) => `<td class="py-2 px-4 font-mono">${v}</td>`).join("")}
  </tr>`;
}

function fmtMs(ms: number): string {
  return ms ? `${ms.toFixed(1)} ms` : "—";
}
function fmtBytes(b: number): string {
  return b ? `${b} B` : "—";
}

function renderHowItWorksModal(): string {
  return `
    <div id="modal-how" class="fixed inset-0 bg-black/60 backdrop-blur-sm hidden z-50 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-labelledby="modal-title">
      <div class="bg-zinc-900 border border-zinc-700 rounded-2xl max-w-2xl w-full max-h-[80vh] overflow-y-auto p-8">
        <div class="flex justify-between items-start mb-6">
          <h2 id="modal-title" class="text-xl font-bold text-zinc-100">How It Works</h2>
          <button id="btn-close-modal" class="text-zinc-400 hover:text-zinc-300 text-xl" aria-label="Close">✕</button>
        </div>

        <div class="space-y-6 text-sm text-zinc-300">
          <div>
            <h3 class="font-semibold text-amber-400 mb-2">The two-party model</h3>
            <p>Asymmetric encryption is <em>directional</em>: Alice seals a letter to <span class="text-emerald-300">Bob's public key</span>, and only <span class="text-emerald-300">Bob's private key</span> can open it — not Alice's, and not Eve's. Use the seal panel to encrypt to Bob, open it with Bob's key, then hit "Try opening with Eve's WRONG key" to watch a real ${term("AES-GCM")} authentication failure. Both ECIES and RSA here are <strong>hybrid</strong>: the slow public-key math only protects a fast symmetric ${term("AES-GCM", "AES-GCM")} key, which does the bulk encryption.</p>
          </div>

          <div>
            <h3 class="font-semibold text-amber-400 mb-2">ECIES P-256 Pipeline</h3>
            <div class="bg-zinc-950 rounded-lg p-4 font-mono text-xs text-zinc-400 space-y-1">
              <p>1. Generate ephemeral ECDH keypair (P-256)</p>
              <p>2. ECDH: ephemeral private × recipient public → shared secret</p>
              <p>3. HKDF-SHA256: shared secret → AES-256 key</p>
              <p>4. AES-256-GCM encrypt message with derived key</p>
              <p>5. Output: ephemeral public key ‖ IV ‖ ciphertext</p>
            </div>
            <p class="mt-2 text-zinc-400 text-xs">Public key: 65 bytes (uncompressed point). Same 128-bit security level as RSA-3072.</p>
          </div>

          <div>
            <h3 class="font-semibold text-amber-400 mb-2">RSA-OAEP Hybrid</h3>
            <div class="bg-zinc-950 rounded-lg p-4 font-mono text-xs text-zinc-400 space-y-1">
              <p>1. Generate random AES-256-GCM key</p>
              <p>2. RSA-OAEP encrypt AES key with recipient's RSA public key</p>
              <p>3. AES-256-GCM encrypt message with AES key</p>
              <p>4. Output: wrapped AES key ‖ IV ‖ ciphertext</p>
            </div>
            <p class="mt-2 text-zinc-400 text-xs">RSA-2048 public key: ~294 bytes (SPKI). RSA-4096: ~550 bytes.</p>
          </div>

          <div>
            <h3 class="font-semibold text-amber-400 mb-2">Key takeaway</h3>
            <p>ECIES achieves equivalent security with dramatically smaller keys (65 bytes vs 294–550 bytes), faster keygen, and compact ciphertexts. Both approaches are hybrid — the asymmetric part protects a symmetric key, which does the actual encryption.</p>
          </div>
        </div>
      </div>
    </div>
  `;
}

// ── Event Binding ────────────────────────────────────────────────────

function bindEvents() {
  if (copyUrlTimerId !== null) {
    clearTimeout(copyUrlTimerId);
    copyUrlTimerId = null;
  }

  document.getElementById("btn-theme")?.addEventListener("click", () => {
    const nextTheme: Theme = getCurrentTheme() === "dark" ? "light" : "dark";
    applyTheme(nextTheme);
  });

  // Tab switching
  document.querySelectorAll<HTMLButtonElement>("[data-tab]").forEach((btn) => {
    btn.addEventListener("click", () => {
      currentTab = btn.dataset["tab"] as Tab;
      render();
    });
  });

  // How it works modal
  document.getElementById("btn-how")?.addEventListener("click", () => {
    document.getElementById("modal-how")?.classList.remove("hidden");
  });
  document.getElementById("btn-close-modal")?.addEventListener("click", closeModal);
  document.getElementById("modal-how")?.addEventListener("click", (e) => {
    if (e.target === e.currentTarget) closeModal();
  });
  bindGlobalListeners();

  // Tab keyboard navigation (arrow keys)
  document.querySelectorAll<HTMLButtonElement>("[data-tab]").forEach((btn) => {
    btn.addEventListener("keydown", (e) => {
      const tabs = Array.from(document.querySelectorAll<HTMLButtonElement>("[data-tab]"));
      const idx = tabs.indexOf(btn);
      let next = -1;
      if (e.key === "ArrowRight") next = (idx + 1) % tabs.length;
      else if (e.key === "ArrowLeft") next = (idx - 1 + tabs.length) % tabs.length;
      if (next >= 0) {
        e.preventDefault();
        tabs[next]!.focus();
        tabs[next]!.click();
      }
    });
  });

  // Benchmark (Compare tab)
  document.getElementById("btn-benchmark")?.addEventListener("click", () => {
    void runBenchmark();
  });

  if (currentTab === "compare") return;
  const algo = currentTab;

  // Restore QR content if it was visible before re-render
  if (qrVisible[algo] && state[algo].publicKeyB64) {
    const container = document.getElementById("qr-container");
    if (container) {
      const url = buildShareUrl(state[algo].publicKeyB64, algo);
      container.innerHTML = generateQrSvg(url, 200);
    }
  }

  // Keygen
  document.getElementById("btn-keygen")?.addEventListener("click", async (e) => {
    await withBusy(e.currentTarget as HTMLButtonElement, "Generating…", () => doKeygen(algo));
    render();
  });

  // Seal
  document.getElementById("btn-seal")?.addEventListener("click", async (e) => {
    await withBusy(e.currentTarget as HTMLButtonElement, "Sealing…", () => doSeal(algo));
    render();
  });

  // Open
  document.getElementById("btn-open")?.addEventListener("click", async (e) => {
    await withBusy(e.currentTarget as HTMLButtonElement, "Opening…", () => doOpen(algo));
  });

  // Open with the WRONG (Eve's) private key — proves asymmetry by failing loudly.
  document.getElementById("btn-open-wrong")?.addEventListener("click", async (e) => {
    await withBusy(e.currentTarget as HTMLButtonElement, "Trying Eve's key…", () => doOpenWrong(algo));
  });

  // Copy ciphertext
  document.getElementById("btn-copy-ct")?.addEventListener("click", async () => {
    await navigator.clipboard.writeText(state[algo].ciphertext);
    // currentTarget is null after the await, so re-query the button.
    const btn = document.getElementById("btn-copy-ct");
    if (btn) btn.textContent = "✓ Copied!";
    announce("Ciphertext copied to clipboard");
    setTimeout(() => {
      const el = document.getElementById("btn-copy-ct");
      if (el) el.innerHTML = `<span aria-hidden="true">📋</span> Copy`;
    }, 1500);
  });

  // Copy share URL
  document.getElementById("btn-copy-url")?.addEventListener("click", async () => {
    const url = buildShareUrl(state[algo].publicKeyB64, algo);
    await navigator.clipboard.writeText(url);
    const btn = document.getElementById("btn-copy-url")!;
    btn.textContent = "✓ Copied!";
    announce("Share URL copied to clipboard");
    if (copyUrlTimerId !== null) clearTimeout(copyUrlTimerId);
    copyUrlTimerId = setTimeout(() => {
      copyUrlTimerId = null;
      const el = document.getElementById("btn-copy-url");
      if (el) el.textContent = "📋 Copy share URL";
    }, 1500);
  });

  // QR code
  document.getElementById("btn-qr")?.addEventListener("click", () => {
    const container = document.getElementById("qr-container")!;
    qrVisible[algo] = !qrVisible[algo];
    if (qrVisible[algo]) {
      const url = buildShareUrl(state[algo].publicKeyB64, algo);
      container.innerHTML = generateQrSvg(url, 200);
      container.classList.remove("hidden");
    } else {
      container.classList.add("hidden");
    }
  });
}

// ── Crypto Operations ────────────────────────────────────────────────

async function doKeygen(algo: "ecies" | "rsa2048" | "rsa4096") {
  const s = state[algo];
  if (algo === "ecies") {
    // Generate THREE independent keypairs so the two-party model is real:
    //   Alice  = "You" (the historical publicKey/privateKey fields; sender)
    //   Bob    = the recipient (his public key is the seal default)
    //   Eve    = an eavesdropper (her private key is the "wrong key" demo)
    const { result: aliceKp, timeMs } = await measure(() => ecies.generateKeypair());
    const [bobKp, eveKp] = await Promise.all([
      ecies.generateKeypair(),
      ecies.generateKeypair(),
    ]);
    const [aliceEx, bobEx, eveEx] = await Promise.all([
      ecies.exportKeys(aliceKp),
      ecies.exportKeys(bobKp),
      ecies.exportKeys(eveKp),
    ]);
    s.publicKey = aliceKp.publicKey;
    s.privateKey = aliceKp.privateKey;
    s.publicKeyB64 = aliceEx.publicKeyB64;
    s.privateKeyB64 = aliceEx.privateKeyB64;
    s.bob = { publicKey: bobKp.publicKey, privateKey: bobKp.privateKey, publicKeyB64: bobEx.publicKeyB64, privateKeyB64: bobEx.privateKeyB64 };
    s.eve = { publicKey: eveKp.publicKey, privateKey: eveKp.privateKey, publicKeyB64: eveEx.publicKeyB64, privateKeyB64: eveEx.privateKeyB64 };
    s.metrics.keygenTimeMs = timeMs;
    s.metrics.publicKeySizeBytes = aliceEx.publicKeyRaw.byteLength;
    s.metrics.privateKeySizeBytes = aliceEx.privateKeyPkcs8.byteLength;
    // Compute the REAL ECDH convergence between an ephemeral key and Bob's key,
    // so the visualization shows Alice's and Bob's sides landing on identical bytes.
    s.ecdhDemo = await ecies.deriveEcdhDemo(bobKp);
  } else {
    const bits = algo === "rsa2048" ? 2048 : 4096;
    const { result: aliceKp, timeMs } = await measure(() => rsa.generateKeypair(bits as rsa.RsaKeySize));
    const [bobKp, eveKp] = await Promise.all([
      rsa.generateKeypair(bits as rsa.RsaKeySize),
      rsa.generateKeypair(bits as rsa.RsaKeySize),
    ]);
    const [aliceEx, bobEx, eveEx] = await Promise.all([
      rsa.exportKeys(aliceKp),
      rsa.exportKeys(bobKp),
      rsa.exportKeys(eveKp),
    ]);
    s.publicKey = aliceKp.publicKey;
    s.privateKey = aliceKp.privateKey;
    s.publicKeyB64 = aliceEx.publicKeyB64;
    s.privateKeyB64 = aliceEx.privateKeyB64;
    s.bob = { publicKey: bobKp.publicKey, privateKey: bobKp.privateKey, publicKeyB64: bobEx.publicKeyB64, privateKeyB64: bobEx.privateKeyB64 };
    s.eve = { publicKey: eveKp.publicKey, privateKey: eveKp.privateKey, publicKeyB64: eveEx.publicKeyB64, privateKeyB64: eveEx.privateKeyB64 };
    s.metrics.keygenTimeMs = timeMs;
    s.metrics.publicKeySizeBytes = aliceEx.publicKeySpki.byteLength;
    s.metrics.privateKeySizeBytes = aliceEx.privateKeyPkcs8.byteLength;
    s.ecdhDemo = null;
  }
}

async function doSeal(algo: "ecies" | "rsa2048" | "rsa4096") {
  const s = state[algo];
  s.sealStatus = null;
  const recipientPkB64 = (document.getElementById("seal-recipient-pk") as HTMLInputElement).value.trim();
  const message = (document.getElementById("seal-message") as HTMLTextAreaElement).value;

  if (!recipientPkB64 || !message) {
    s.sealStatus = { kind: "error", text: "Enter a recipient public key and a message to seal." };
    announce(s.sealStatus.text);
    return;
  }

  const plaintext = new TextEncoder().encode(message);
  try {
    if (algo === "ecies") {
      const pubKey = await ecies.importPublicKey(recipientPkB64);
      const { result: envelope, timeMs } = await measure(() => ecies.seal(pubKey, plaintext));
      s.ciphertext = ecies.serializeEnvelope(envelope);
      s.metrics.encryptTimeMs = timeMs;
      s.metrics.ciphertextSizeBytes = envelope.ephemeralPub.length + envelope.iv.length + envelope.ciphertext.length;
    } else {
      const pubKey = await rsa.importPublicKey(recipientPkB64);
      const { result: envelope, timeMs } = await measure(() => rsa.seal(pubKey, plaintext));
      const keySize = algo === "rsa2048" ? 2048 : 4096;
      s.ciphertext = rsa.serializeEnvelope(envelope, keySize as rsa.RsaKeySize);
      s.metrics.encryptTimeMs = timeMs;
      s.metrics.ciphertextSizeBytes = envelope.wrappedKey.length + envelope.iv.length + envelope.ciphertext.length;
    }
    announce(`Letter sealed — ${s.metrics.ciphertextSizeBytes} bytes.`);
  } catch (error) {
    const messageText = error instanceof Error ? error.message : "Encryption failed.";
    s.sealStatus = { kind: "error", text: messageText };
    announce(messageText);
  }
}

async function doOpen(algo: "ecies" | "rsa2048" | "rsa4096") {
  const s = state[algo];
  const privKeyB64 = (document.getElementById("open-privkey") as HTMLInputElement).value.trim();
  const ctText = (document.getElementById("open-ciphertext") as HTMLTextAreaElement).value.trim();

  if (!privKeyB64 || !ctText) return;

  try {
    let plaintext: Uint8Array;
    let timeMs: number;

    if (algo === "ecies") {
      const privKey = await ecies.importPrivateKey(privKeyB64);
      const envelope = ecies.deserializeEnvelope(ctText);
      ({ result: plaintext, timeMs } = await measure(() => ecies.open(privKey, envelope)));
    } else {
      const privKey = await rsa.importPrivateKey(privKeyB64);
      const keySize = algo === "rsa2048" ? 2048 : 4096;
      const envelope = rsa.deserializeEnvelope(ctText, keySize as rsa.RsaKeySize);
      ({ result: plaintext, timeMs } = await measure(() => rsa.open(privKey, envelope)));
    }

    s.metrics.decryptTimeMs = timeMs;

    const decoded = new TextDecoder().decode(plaintext);
    showResultMessage(decoded, false, `Decrypted Message — ${timeMs.toFixed(1)}ms`);
  } catch (e) {
    const messageText = e instanceof Error ? e.message : "Decryption failed.";
    announce(messageText);
    showResultMessage(messageText, true);
  }
}

// The security-boundary demo: attempt to open Alice's letter to Bob using
// EVE's private key. This is a REAL decrypt attempt against the real envelope.
// For ECIES, Eve's ECDH secret differs from Bob's, so the derived AES key is
// wrong and the GCM tag check fails. For RSA, OAEP unwrap of the key with the
// wrong modulus fails. Either way, no plaintext is produced — that failure is
// exactly what asymmetry guarantees.
async function doOpenWrong(algo: "ecies" | "rsa2048" | "rsa4096") {
  const s = state[algo];
  const ctText = (document.getElementById("open-ciphertext") as HTMLTextAreaElement).value.trim() || s.ciphertext;
  if (!s.eve.privateKeyB64 || !ctText) return;

  try {
    if (algo === "ecies") {
      const eve = await ecies.importPrivateKey(s.eve.privateKeyB64);
      const envelope = ecies.deserializeEnvelope(ctText);
      await ecies.open(eve, envelope);
    } else {
      const keySize = algo === "rsa2048" ? 2048 : 4096;
      const eve = await rsa.importPrivateKey(s.eve.privateKeyB64);
      const envelope = rsa.deserializeEnvelope(ctText, keySize as rsa.RsaKeySize);
      await rsa.open(eve, envelope);
    }
    // Reaching here would mean the wrong key decrypted — cryptographically it
    // should be impossible. Report it honestly rather than hide it.
    const msg = "Unexpected: Eve's key opened the letter. This should never happen — please report it.";
    announce(msg);
    showResultMessage(msg, true, "Eve's attempt");
  } catch {
    const msg =
      algo === "ecies"
        ? "Rejected. Eve's ECDH secret ≠ Bob's, so the AES-GCM authentication tag failed. The wrong private key cannot open the letter — this is asymmetry in action."
        : "Rejected. RSA-OAEP unwrap with Eve's key failed, so no AES key was recovered. The wrong private key cannot open the letter — this is asymmetry in action.";
    announce("Decryption with the wrong key failed, as expected.");
    showResultMessage(msg, true, "Eve's attempt — failed as expected ✓");
  }
}

// ── Benchmark (Compare tab) ──────────────────────────────────────────

async function runBenchmark() {
  if (benchmarkRunning) return;
  benchmarkRunning = true;
  render();

  const algos: ("ecies" | "rsa2048" | "rsa4096")[] = ["ecies", "rsa2048", "rsa4096"];
  const labels = { ecies: "ECIES P-256", rsa2048: "RSA-2048", rsa4096: "RSA-4096" } as const;
  try {
    for (const algo of algos) {
      announce(`Benchmarking ${labels[algo]}…`);
      await benchmarkAlgo(algo);
      render(); // progressively fill the table; button stays disabled until done
    }
    announce("Benchmark complete.");
  } finally {
    benchmarkRunning = false;
    render();
  }
}

async function benchmarkAlgo(algo: "ecies" | "rsa2048" | "rsa4096") {
  // Keygen is the expensive, high-variance op — a single sample is honest.
  // The benchmark measures ONE keypair (not the seal/open workbench's Alice+Bob+Eve
  // trio) so the reported keygen time reflects a single generateKey call.
  const s = state[algo];
  if (algo === "ecies") {
    const { result: kp, timeMs } = await measure(() => ecies.generateKeypair());
    const exported = await ecies.exportKeys(kp);
    s.publicKey = kp.publicKey;
    s.privateKey = kp.privateKey;
    s.publicKeyB64 = exported.publicKeyB64;
    s.privateKeyB64 = exported.privateKeyB64;
    s.metrics.keygenTimeMs = timeMs;
    s.metrics.publicKeySizeBytes = exported.publicKeyRaw.byteLength;
    s.metrics.privateKeySizeBytes = exported.privateKeyPkcs8.byteLength;
  } else {
    const bits = algo === "rsa2048" ? 2048 : 4096;
    const { result: kp, timeMs } = await measure(() => rsa.generateKeypair(bits as rsa.RsaKeySize));
    const exported = await rsa.exportKeys(kp);
    s.publicKey = kp.publicKey;
    s.privateKey = kp.privateKey;
    s.publicKeyB64 = exported.publicKeyB64;
    s.privateKeyB64 = exported.privateKeyB64;
    s.metrics.keygenTimeMs = timeMs;
    s.metrics.publicKeySizeBytes = exported.publicKeySpki.byteLength;
    s.metrics.privateKeySizeBytes = exported.privateKeyPkcs8.byteLength;
  }
  if (!s.publicKey || !s.privateKey) return;

  if (algo === "ecies") {
    const enc = await measureAverage(() => ecies.seal(s.publicKey!, BENCH_MESSAGE), BENCH_ITERATIONS);
    const envelope = enc.result;
    s.ciphertext = ecies.serializeEnvelope(envelope);
    s.metrics.encryptTimeMs = enc.timeMs;
    s.metrics.ciphertextSizeBytes = envelope.ephemeralPub.length + envelope.iv.length + envelope.ciphertext.length;
    const dec = await measureAverage(() => ecies.open(s.privateKey!, envelope), BENCH_ITERATIONS);
    s.metrics.decryptTimeMs = dec.timeMs;
  } else {
    const keySize = algo === "rsa2048" ? 2048 : 4096;
    const enc = await measureAverage(() => rsa.seal(s.publicKey!, BENCH_MESSAGE), BENCH_ITERATIONS);
    const envelope = enc.result;
    s.ciphertext = rsa.serializeEnvelope(envelope, keySize as rsa.RsaKeySize);
    s.metrics.encryptTimeMs = enc.timeMs;
    s.metrics.ciphertextSizeBytes = envelope.wrappedKey.length + envelope.iv.length + envelope.ciphertext.length;
    const dec = await measureAverage(() => rsa.open(s.privateKey!, envelope), BENCH_ITERATIONS);
    s.metrics.decryptTimeMs = dec.timeMs;
  }
}

// ── Helpers ──────────────────────────────────────────────────────────

async function withBusy(
  btn: HTMLButtonElement,
  busyLabel: string,
  fn: () => Promise<void>
): Promise<void> {
  const original = btn.innerHTML;
  btn.disabled = true;
  btn.setAttribute("aria-busy", "true");
  btn.innerHTML = `<span class="spinner" aria-hidden="true"></span> ${escapeHtml(busyLabel)}`;
  try {
    await fn();
  } finally {
    // The surrounding handler usually re-renders (replacing this node), but
    // restore state anyway for the open button, which does not re-render.
    btn.disabled = false;
    btn.removeAttribute("aria-busy");
    btn.innerHTML = original;
  }
}

function escapeHtml(s: string): string {
  const div = document.createElement("div");
  div.appendChild(document.createTextNode(s));
  return div.innerHTML;
}

function announce(message: string) {
  const el = document.getElementById("status-announcer");
  if (el) el.textContent = message;
}

function bindGlobalListeners() {
  if (globalListenersBound) return;

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeModal();
  });

  globalListenersBound = true;
}

function showResultMessage(message: string, isError: boolean, label = "Decrypted Message") {
  const resultDiv = document.getElementById("open-result");
  const ptDiv = document.getElementById("open-plaintext");
  const labelEl = resultDiv?.querySelector("label");

  if (!resultDiv || !ptDiv || !labelEl) return;

  labelEl.textContent = label;
  ptDiv.textContent = message;
  ptDiv.className = isError
    ? "text-sm text-red-400 bg-zinc-950 p-3 rounded-lg border border-red-800"
    : "text-sm text-zinc-100 bg-zinc-950 p-3 rounded-lg border border-emerald-800";
  resultDiv.classList.remove("hidden");
}

function closeModal() {
  const modal = document.getElementById("modal-how");
  if (modal && !modal.classList.contains("hidden")) {
    modal.classList.add("hidden");
    document.getElementById("btn-how")?.focus();
  }
}

// ── Deep link handling ───────────────────────────────────────────────

function handleDeepLink() {
  const params = parseCurrentUrl();
  if (!params) return;

  currentTab = params.algo === "ecies" ? "ecies" : params.algo === "rsa2048" ? "rsa2048" : "rsa4096";
  state[currentTab].recipientB64 = params.pk;
  render();
}

// ── Init ─────────────────────────────────────────────────────────────

if (!document.documentElement.getAttribute("data-theme")) {
  applyTheme("dark");
}

render();
handleDeepLink();

if (checkWebCrypto()) {
  void runStartupSelfTest().then((result) => {
    selfTestState = result.ok
      ? { status: "passed", message: result.message }
      : { status: "failed", message: result.message };
    render();
    if (!result.ok) announce(result.message);
  });
}
