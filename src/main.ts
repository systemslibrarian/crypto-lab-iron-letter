// ── Iron Letter — Main Entry ─────────────────────────────────────────

import "./style.css";
import * as ecies from "./crypto/ecies";
import * as rsa from "./crypto/rsa";
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

interface AlgoState {
  publicKey: CryptoKey | null;
  privateKey: CryptoKey | null;
  publicKeyB64: string;
  privateKeyB64: string;
  ciphertext: string;
  metrics: Metrics;
  sealStatus: { kind: "ok" | "error"; text: string } | null;
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
let deepLinkRecipient: { algo: Exclude<Tab, "compare">; publicKeyB64: string } | null = null;
type Theme = "dark" | "light";
let copyUrlTimerId: ReturnType<typeof setTimeout> | null = null;
const qrVisible: Record<"ecies" | "rsa2048" | "rsa4096", boolean> = { ecies: false, rsa2048: false, rsa4096: false };

const state: Record<"ecies" | "rsa2048" | "rsa4096", AlgoState> = {
  ecies: { publicKey: null, privateKey: null, publicKeyB64: "", privateKeyB64: "", ciphertext: "", metrics: emptyMetrics(), sealStatus: null },
  rsa2048: { publicKey: null, privateKey: null, publicKeyB64: "", privateKeyB64: "", ciphertext: "", metrics: emptyMetrics(), sealStatus: null },
  rsa4096: { publicKey: null, privateKey: null, publicKeyB64: "", privateKeyB64: "", ciphertext: "", metrics: emptyMetrics(), sealStatus: null },
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
      <header class="mb-8 text-center relative">
        <button
          id="btn-theme"
          type="button"
          class="theme-toggle"
          aria-label="${themeState.ariaLabel}"
        >${themeState.icon}</button>
        <h1 class="text-3xl font-bold tracking-tight text-zinc-100">
          <span class="text-amber-400">⛒</span> Iron Letter
        </h1>
        <p class="mt-2 text-sm text-zinc-400">
          Asymmetric encryption in the browser — ECIES P-256 vs RSA-OAEP, side by side.
        </p>
        <p class="text-xs text-zinc-600 mt-1">Seal a letter. Only one key can open it.</p>
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
        <button id="btn-how" class="text-xs text-zinc-500 hover:text-zinc-300 underline underline-offset-4 transition-colors">
          How It Works
        </button>
        <p class="text-xs text-zinc-600 mt-2">
          All cryptography runs locally via WebCrypto. Private keys never leave your browser.
        </p>
        <p style="font-size: 0.85rem; opacity: 0.7; margin-top: 1.5rem;">
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
    return `<div class="text-sm text-red-500 text-center mb-4 p-3 border border-red-800 rounded-lg bg-red-950" role="alert">
    WebCrypto unavailable. This app requires a secure context (HTTPS or localhost).
  </div>`;
  }

  if (selfTestState.status === "running") {
    return `<div class="text-xs text-amber-400 text-center mb-4" role="status">${selfTestState.message}</div>`;
  }

  if (selfTestState.status === "passed") {
    return `<div class="text-xs text-emerald-500 text-center mb-4" role="status">${selfTestState.message}</div>`;
  }

  return `<div class="text-sm text-red-500 text-center mb-4 p-3 border border-red-800 rounded-lg bg-red-950" role="alert">
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

function renderAlgoPanel(algo: "ecies" | "rsa2048" | "rsa4096"): string {
  const s = state[algo];
  const m = s.metrics;
  let recipientPublicKey = s.publicKeyB64;
  if (deepLinkRecipient?.algo === algo) {
    recipientPublicKey = deepLinkRecipient.publicKeyB64;
    deepLinkRecipient = null;
  }
  const algoLabel =
    algo === "ecies" ? "ECIES P-256" : algo === "rsa2048" ? "RSA-2048" : "RSA-4096";

  return `
    <div class="space-y-6">
      <!-- Keygen Panel -->
      <section class="bg-zinc-900 rounded-xl p-6 border border-zinc-800">
        <h2 class="text-lg font-semibold text-zinc-200 mb-4"><span aria-hidden="true">🔑</span> Key Generation</h2>
        <button id="btn-keygen" class="min-h-[44px] px-4 py-2 rounded-lg bg-amber-500 text-zinc-950 font-medium text-sm hover:bg-amber-400 transition-colors focus:outline-2 focus:outline-amber-400 focus:outline-offset-2">
          Generate ${algoLabel} Keypair
        </button>
        ${
          s.publicKeyB64
            ? `
          <div class="mt-4 space-y-3">
            <div>
              <label class="text-xs text-zinc-400 block mb-1">Public Key (${m.publicKeySizeBytes} bytes) — ${m.keygenTimeMs.toFixed(1)}ms</label>
              <div class="font-mono text-xs text-emerald-400 bg-zinc-950 p-3 rounded-lg break-all max-h-24 overflow-y-auto" role="region" aria-label="Public key value">${escapeHtml(s.publicKeyB64)}</div>
            </div>
            <div>
              <label class="text-xs text-zinc-400 block mb-1">Private Key (${m.privateKeySizeBytes} bytes)</label>
              <details>
                <summary class="text-xs text-zinc-600 cursor-pointer hover:text-zinc-400">Reveal private key</summary>
                <div class="font-mono text-xs text-red-400 bg-zinc-950 p-3 rounded-lg break-all mt-1 max-h-24 overflow-y-auto">${escapeHtml(s.privateKeyB64)}</div>
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
        <h2 class="text-lg font-semibold text-zinc-200 mb-4"><span aria-hidden="true">📨</span> Seal (Encrypt)</h2>
        <div class="space-y-3">
          <div>
            <label for="seal-recipient-pk" class="text-xs text-zinc-400 block mb-1">Recipient Public Key (base64url)</label>
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
          <button id="btn-seal" class="min-h-[44px] px-4 py-2 rounded-lg bg-emerald-600 text-white font-medium text-sm hover:bg-emerald-500 transition-colors focus:outline-2 focus:outline-emerald-400 focus:outline-offset-2">
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
                <label class="text-xs text-zinc-400">Ciphertext (${m.ciphertextSizeBytes} bytes) — ${m.encryptTimeMs.toFixed(1)}ms</label>
                <button id="btn-copy-ct" aria-label="Copy ciphertext to clipboard" class="min-h-[44px] min-w-[44px] px-3 py-2 text-xs rounded-lg bg-zinc-800 text-zinc-300 hover:bg-zinc-700 transition-colors focus:outline-2 focus:outline-amber-400 focus:outline-offset-2">
                  <span aria-hidden="true">📋</span> Copy
                </button>
              </div>
              <div class="font-mono text-xs text-sky-400 bg-zinc-950 p-3 rounded-lg break-all max-h-32 overflow-y-auto" role="region" aria-label="Encrypted ciphertext">${escapeHtml(s.ciphertext)}</div>
            </div>
          `
              : ""
          }
        </div>
      </section>

      <!-- Open Panel -->
      <section class="bg-zinc-900 rounded-xl p-6 border border-zinc-800">
        <h2 class="text-lg font-semibold text-zinc-200 mb-4"><span aria-hidden="true">📬</span> Open (Decrypt)</h2>
        <div class="space-y-3">
          <div>
            <label for="open-privkey" class="text-xs text-zinc-400 block mb-1">Private Key (base64url)</label>
            <input id="open-privkey" type="text" value="${escapeHtml(s.privateKeyB64)}"
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
          <button id="btn-open" class="min-h-[44px] px-4 py-2 rounded-lg bg-violet-600 text-white font-medium text-sm hover:bg-violet-500 transition-colors focus:outline-2 focus:outline-violet-400 focus:outline-offset-2">
            Open Letter
          </button>
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
      <p class="text-xs text-zinc-500 mb-4">
        One click generates a keypair for each algorithm and averages encrypt/decrypt over ${BENCH_ITERATIONS} runs — no manual setup needed.
      </p>
      ${
        !hasData
          ? `<p class="text-sm text-zinc-500">Run the benchmark above, or generate keys and encrypt messages in each tab, to see comparisons.</p>`
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
        <p class="text-xs text-zinc-500 mt-3">
          Security level is the approximate symmetric-equivalent strength (NIST SP 800-57). Note the takeaway:
          RSA-2048's far larger key is actually <em>weaker</em> than ECIES P-256's 65-byte key.
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
          <button id="btn-close-modal" class="text-zinc-500 hover:text-zinc-300 text-xl" aria-label="Close">✕</button>
        </div>

        <div class="space-y-6 text-sm text-zinc-300">
          <div>
            <h3 class="font-semibold text-amber-400 mb-2">ECIES P-256 Pipeline</h3>
            <div class="bg-zinc-950 rounded-lg p-4 font-mono text-xs text-zinc-400 space-y-1">
              <p>1. Generate ephemeral ECDH keypair (P-256)</p>
              <p>2. ECDH: ephemeral private × recipient public → shared secret</p>
              <p>3. HKDF-SHA256: shared secret → AES-256 key</p>
              <p>4. AES-256-GCM encrypt message with derived key</p>
              <p>5. Output: ephemeral public key ‖ IV ‖ ciphertext</p>
            </div>
            <p class="mt-2 text-zinc-500 text-xs">Public key: 65 bytes (uncompressed point). Same 128-bit security level as RSA-3072.</p>
          </div>

          <div>
            <h3 class="font-semibold text-amber-400 mb-2">RSA-OAEP Hybrid</h3>
            <div class="bg-zinc-950 rounded-lg p-4 font-mono text-xs text-zinc-400 space-y-1">
              <p>1. Generate random AES-256-GCM key</p>
              <p>2. RSA-OAEP encrypt AES key with recipient's RSA public key</p>
              <p>3. AES-256-GCM encrypt message with AES key</p>
              <p>4. Output: wrapped AES key ‖ IV ‖ ciphertext</p>
            </div>
            <p class="mt-2 text-zinc-500 text-xs">RSA-2048 public key: ~294 bytes (SPKI). RSA-4096: ~550 bytes.</p>
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
  await doKeygen(algo);
  const s = state[algo];
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
  deepLinkRecipient = { algo: currentTab, publicKeyB64: params.pk };
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
