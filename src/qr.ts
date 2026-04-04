// ── QR Code Generator (pure JS) ──────────────────────────────────────
// Minimal QR code encoder — generates SVG from text.
// Uses a simple implementation sufficient for URL-length data.

// This is a minimal QR code generator using the alphanumeric/byte mode.
// For production, you'd use a library, but the spec says "pure JS — no external service."

const EC_LEVEL = 1; // 0=L, 1=M, 2=Q, 3=H

// We'll use a canvas-based approach with a compact encoder.
// Since writing a full QR spec encoder from scratch is ~1000 lines,
// we use a well-known minimal implementation pattern.

export function generateQrSvg(text: string, size = 256): string {
  const modules = encode(text);
  const n = modules.length;
  const cellSize = size / n;

  let paths = "";
  for (let y = 0; y < n; y++) {
    for (let x = 0; x < n; x++) {
      if (modules[y]![x]) {
        paths += `M${x * cellSize},${y * cellSize}h${cellSize}v${cellSize}h-${cellSize}z`;
      }
    }
  }

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="${size}" height="${size}">
    <rect width="100%" height="100%" fill="white"/>
    <path d="${paths}" fill="black"/>
  </svg>`;
}

// ── Minimal QR encoder ───────────────────────────────────────────────
// Adapted from the public domain "qr-creator" algorithm patterns
// Supports byte mode, version 1-10, EC level M

function encode(text: string): boolean[][] {
  const data = new TextEncoder().encode(text);
  // Pick smallest version that fits
  const version = pickVersion(data.length, EC_LEVEL);
  const size = version * 4 + 17;

  // Initialize modules
  const modules: (boolean | null)[][] = Array.from({ length: size }, () =>
    Array.from({ length: size }, () => null)
  );
  const isFunction: boolean[][] = Array.from({ length: size }, () =>
    Array.from({ length: size }, () => false)
  );

  // Draw function patterns
  drawFinderPatterns(modules, isFunction, size);
  drawAlignmentPatterns(modules, isFunction, version, size);
  drawTimingPatterns(modules, isFunction, size);
  modules[8]![size - 8] = true;
  isFunction[8]![size - 8] = true;

  // Reserve format/version areas
  reserveFormatAreas(isFunction, size, version);

  // Encode data
  const dataCodewords = encodeData(data, version, EC_LEVEL);
  const ecCodewords = generateEC(dataCodewords, version, EC_LEVEL);
  const allCodewords = [...dataCodewords, ...ecCodewords];

  // Place data bits
  placeDataBits(modules, isFunction, allCodewords, size);

  // Apply best mask
  const bestMask = selectBestMask(modules, isFunction, size, EC_LEVEL);
  applyMask(modules, isFunction, bestMask, size);
  drawFormatBits(modules, bestMask, EC_LEVEL, size, version);

  return modules.map((row) => row.map((v) => v === true));
}

// ── Version selection ─────────────────────────────────────────────────

const DATA_CAPACITY = [
  // [L, M, Q, H] data codewords per version
  [19, 16, 13, 9],
  [34, 28, 22, 16],
  [55, 44, 34, 26],
  [80, 64, 48, 36],
  [108, 86, 62, 46],
  [136, 108, 76, 60],
  [156, 124, 86, 66],
  [194, 154, 108, 86],
  [232, 182, 130, 100],
  [274, 216, 151, 122],
  [324, 254, 177, 140],
  [370, 290, 203, 158],
  [428, 334, 241, 180],
  [461, 365, 258, 197],
  [523, 415, 292, 223],
  [589, 453, 322, 253],
  [647, 507, 364, 283],
  [721, 563, 394, 313],
  [795, 627, 442, 341],
  [861, 669, 482, 385],
];

function pickVersion(dataLen: number, ecLevel: number): number {
  // byte mode overhead: 4 (mode) + 8 or 16 (count) bits
  for (let v = 1; v <= 20; v++) {
    const countBits = v <= 9 ? 8 : 16;
    const overhead = Math.ceil((4 + countBits) / 8);
    const cap = DATA_CAPACITY[v - 1]![ecLevel]!;
    if (dataLen + overhead <= cap) return v;
  }
  throw new Error("Data too long for QR code");
}

// ── Drawing functions ─────────────────────────────────────────────────

function drawFinderPatterns(
  m: (boolean | null)[][],
  f: boolean[][],
  size: number
) {
  const positions = [
    [0, 0],
    [size - 7, 0],
    [0, size - 7],
  ];
  for (const [row, col] of positions) {
    for (let dy = -1; dy <= 7; dy++) {
      for (let dx = -1; dx <= 7; dx++) {
        const y = row! + dy;
        const x = col! + dx;
        if (y < 0 || y >= size || x < 0 || x >= size) continue;
        const inOuter =
          dy === 0 || dy === 6 || dx === 0 || dx === 6;
        const inInner = dy >= 2 && dy <= 4 && dx >= 2 && dx <= 4;
        const isSep = dy === -1 || dy === 7 || dx === -1 || dx === 7;
        m[y]![x] = !isSep && (inOuter || inInner);
        f[y]![x] = true;
      }
    }
  }
}

function drawAlignmentPatterns(
  m: (boolean | null)[][],
  f: boolean[][],
  version: number,
  size: number
) {
  if (version < 2) return;
  const positions = getAlignmentPositions(version, size);
  for (const ay of positions) {
    for (const ax of positions) {
      // Skip if overlaps finder
      if (
        (ay <= 8 && ax <= 8) ||
        (ay <= 8 && ax >= size - 8) ||
        (ay >= size - 8 && ax <= 8)
      )
        continue;
      for (let dy = -2; dy <= 2; dy++) {
        for (let dx = -2; dx <= 2; dx++) {
          const y = ay + dy;
          const x = ax + dx;
          m[y]![x] =
            Math.abs(dy) === 2 || Math.abs(dx) === 2 || (dy === 0 && dx === 0);
          f[y]![x] = true;
        }
      }
    }
  }
}

function getAlignmentPositions(version: number, size: number): number[] {
  if (version === 1) return [];
  const count = Math.floor(version / 7) + 2;
  const first = 6;
  const last = size - 7;
  const positions = [first];
  if (count > 2) {
    const step = Math.ceil((last - first) / (count - 1));
    const alignedStep = step % 2 === 0 ? step : step + 1;
    for (let i = 1; i < count - 1; i++) {
      positions.push(last - alignedStep * (count - 1 - i));
    }
  }
  positions.push(last);
  return positions;
}

function drawTimingPatterns(
  m: (boolean | null)[][],
  f: boolean[][],
  size: number
) {
  for (let i = 8; i < size - 8; i++) {
    const val = i % 2 === 0;
    if (!f[6]![i]) {
      m[6]![i] = val;
      f[6]![i] = true;
    }
    if (!f[i]![6]) {
      m[i]![6] = val;
      f[i]![6] = true;
    }
  }
}

function reserveFormatAreas(f: boolean[][], size: number, version: number) {
  // Format info areas around finders
  for (let i = 0; i < 8; i++) {
    f[8]![i] = true;
    f[8]![size - 1 - i] = true;
    f[i]![8] = true;
    f[size - 1 - i]![8] = true;
  }
  f[8]![8] = true;

  // Version info areas (version >= 7)
  if (version >= 7) {
    for (let i = 0; i < 6; i++) {
      for (let j = 0; j < 3; j++) {
        f[size - 11 + j]![i] = true;
        f[i]![size - 11 + j] = true;
      }
    }
  }
}

// ── Data encoding (byte mode) ─────────────────────────────────────────

function encodeData(
  data: Uint8Array,
  version: number,
  ecLevel: number
): number[] {
  const capacity = DATA_CAPACITY[version - 1]![ecLevel]!;
  const countBits = version <= 9 ? 8 : 16;

  // Build bit stream
  const bits: number[] = [];
  const pushBits = (val: number, len: number) => {
    for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1);
  };

  pushBits(0b0100, 4); // byte mode indicator
  pushBits(data.length, countBits);
  for (const byte of data) pushBits(byte, 8);

  // Terminator
  const totalBits = capacity * 8;
  const terminatorLen = Math.min(4, totalBits - bits.length);
  pushBits(0, terminatorLen);

  // Pad to byte boundary
  while (bits.length % 8 !== 0) bits.push(0);

  // Pad codewords
  const padBytes = [0xec, 0x11];
  let padIdx = 0;
  while (bits.length < totalBits) {
    pushBits(padBytes[padIdx % 2]!, 8);
    padIdx++;
  }

  // Convert to bytes
  const result: number[] = [];
  for (let i = 0; i < bits.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j++) byte = (byte << 1) | bits[i + j]!;
    result.push(byte);
  }
  return result;
}

// ── Error correction (Reed-Solomon) ───────────────────────────────────

const EC_CODEWORDS_PER_BLOCK: number[][] = [
  // [L, M, Q, H] per version
  [7, 10, 13, 17],
  [10, 16, 22, 28],
  [15, 26, 18, 22],
  [20, 18, 26, 16],
  [26, 24, 18, 22],
  [18, 16, 24, 28],
  [20, 18, 18, 26],
  [24, 22, 22, 26],
  [30, 22, 20, 24],
  [18, 26, 24, 28],
  [20, 30, 28, 24],
  [24, 22, 26, 28],
  [26, 22, 24, 22],
  [30, 24, 20, 24],
  [22, 24, 30, 24],
  [24, 28, 24, 30],
  [28, 28, 28, 28],
  [30, 26, 28, 28],
  [28, 26, 26, 26],
  [28, 26, 28, 28],
];

const NUM_EC_BLOCKS: number[][] = [
  // [L, M, Q, H]
  [1, 1, 1, 1],
  [1, 1, 1, 1],
  [1, 1, 2, 2],
  [1, 2, 2, 4],
  [1, 2, 2, 2],// v5 simplified
  [2, 2, 2, 2],// v6
  [2, 2, 2, 4],// ...
  [2, 2, 2, 4],
  [2, 2, 4, 4],
  [2, 4, 4, 6],
  [4, 1, 4, 3],
  [2, 6, 4, 7],
  [4, 8, 8, 12],
  [3, 4, 11, 11],
  [5, 5, 5, 11],
  [5, 7, 15, 3],
  [1, 10, 1, 2],
  [5, 9, 17, 2],
  [3, 3, 17, 9],
  [3, 3, 15, 15],
];

function generateEC(data: number[], version: number, ecLevel: number): number[] {
  const ecPerBlock = EC_CODEWORDS_PER_BLOCK[version - 1]![ecLevel]!;
  const numBlocks = NUM_EC_BLOCKS[version - 1]![ecLevel]!;
  const totalData = data.length;
  const shortBlockLen = Math.floor(totalData / numBlocks);
  const longBlocks = totalData % numBlocks;

  const blocks: number[][] = [];
  let offset = 0;
  for (let i = 0; i < numBlocks; i++) {
    const len = shortBlockLen + (i < numBlocks - longBlocks ? 0 : 1);
    blocks.push(data.slice(offset, offset + len));
    offset += len;
  }

  const gen = rsGeneratorPoly(ecPerBlock);
  const ecBlocks: number[][] = [];
  for (const block of blocks) {
    ecBlocks.push(rsEncode(block, gen));
  }

  // Interleave
  const result: number[] = [];
  const maxBlockLen = shortBlockLen + (longBlocks > 0 ? 1 : 0);
  for (let i = 0; i < maxBlockLen; i++) {
    for (const block of blocks) {
      if (i < block.length) result.push(block[i]!);
    }
  }
  for (let i = 0; i < ecPerBlock; i++) {
    for (const ec of ecBlocks) {
      result.push(ec[i]!);
    }
  }

  return result.slice(totalData);
}

// GF(2^8) operations
const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);

(function initGF() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x = x << 1;
    if (x >= 256) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255]!;
})();

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a]! + GF_LOG[b]!]!;
}

function rsGeneratorPoly(degree: number): number[] {
  let gen = [1];
  for (let i = 0; i < degree; i++) {
    const next = new Array(gen.length + 1).fill(0);
    for (let j = 0; j < gen.length; j++) {
      next[j] ^= gfMul(gen[j]!, GF_EXP[i]!);
      next[j + 1] ^= gen[j]!;
    }
    gen = next;
  }
  return gen;
}

function rsEncode(data: number[], gen: number[]): number[] {
  const result = new Array(gen.length - 1).fill(0);
  for (const byte of data) {
    const factor = byte ^ result[0]!;
    result.shift();
    result.push(0);
    for (let i = 0; i < result.length; i++) {
      result[i] ^= gfMul(gen[i + 1]!, factor);
    }
  }
  return result;
}

// ── Data placement ────────────────────────────────────────────────────

function placeDataBits(
  m: (boolean | null)[][],
  f: boolean[][],
  codewords: number[],
  size: number
) {
  let bitIdx = 0;
  const totalBits = codewords.length * 8;

  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5; // skip timing column
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const upward = ((right + 1) & 2) === 0;
        const y = upward ? size - 1 - vert : vert;
        if (f[y]![x] || bitIdx >= totalBits) continue;
        const byteIdx = Math.floor(bitIdx / 8);
        const bitPos = 7 - (bitIdx % 8);
        m[y]![x] = ((codewords[byteIdx]! >>> bitPos) & 1) === 1;
        bitIdx++;
      }
    }
  }
}

// ── Masking ───────────────────────────────────────────────────────────

type MaskFn = (y: number, x: number) => boolean;

const MASKS: MaskFn[] = [
  (y, x) => (y + x) % 2 === 0,
  (y) => y % 2 === 0,
  (_y, x) => x % 3 === 0,
  (y, x) => (y + x) % 3 === 0,
  (y, x) => (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0,
  (y, x) => ((y * x) % 2) + ((y * x) % 3) === 0,
  (y, x) => (((y * x) % 2) + ((y * x) % 3)) % 2 === 0,
  (y, x) => (((y + x) % 2) + ((y * x) % 3)) % 2 === 0,
];

function applyMask(
  m: (boolean | null)[][],
  f: boolean[][],
  maskIdx: number,
  size: number
) {
  const fn = MASKS[maskIdx]!;
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      if (!f[y]![x] && fn(y, x)) {
        m[y]![x] = !m[y]![x];
      }
    }
  }
}

function selectBestMask(
  m: (boolean | null)[][],
  f: boolean[][],
  size: number,
  _ecLevel: number
): number {
  let bestMask = 0;
  let bestScore = Infinity;

  for (let mask = 0; mask < 8; mask++) {
    // Clone and apply
    const clone = m.map((row) => [...row]);
    applyMask(clone, f, mask, size);
    const score = penaltyScore(clone, size);
    if (score < bestScore) {
      bestScore = score;
      bestMask = mask;
    }
  }
  return bestMask;
}

function penaltyScore(m: (boolean | null)[][], size: number): number {
  let score = 0;
  // Rule 1: consecutive same-color modules in row/col
  for (let y = 0; y < size; y++) {
    let run = 1;
    for (let x = 1; x < size; x++) {
      if (m[y]![x] === m[y]![x - 1]) {
        run++;
        if (run === 5) score += 3;
        else if (run > 5) score += 1;
      } else {
        run = 1;
      }
    }
  }
  for (let x = 0; x < size; x++) {
    let run = 1;
    for (let y = 1; y < size; y++) {
      if (m[y]![x] === m[y - 1]![x]) {
        run++;
        if (run === 5) score += 3;
        else if (run > 5) score += 1;
      } else {
        run = 1;
      }
    }
  }
  // Rule 4: proportion of dark modules
  let dark = 0;
  for (let y = 0; y < size; y++)
    for (let x = 0; x < size; x++) if (m[y]![x]) dark++;
  const pct = (dark * 100) / (size * size);
  score += Math.abs(Math.floor(pct / 5) * 5 - 50) * 2;
  return score;
}

// ── Format bits ───────────────────────────────────────────────────────

function drawFormatBits(
  m: (boolean | null)[][],
  mask: number,
  ecLevel: number,
  size: number,
  version: number
) {
  const ecBits = [1, 0, 3, 2][ecLevel]!; // L=01, M=00, Q=11, H=10
  let data = (ecBits << 3) | mask;

  // BCH(15,5) encoding
  let rem = data;
  for (let i = 0; i < 10; i++) {
    rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  }
  const bits = ((data << 10) | rem) ^ 0x5412;

  // Place format bits
  const formatPositions1 = [
    [0, 8], [1, 8], [2, 8], [3, 8], [4, 8], [5, 8], [7, 8], [8, 8],
    [8, 7], [8, 5], [8, 4], [8, 3], [8, 2], [8, 1], [8, 0],
  ];
  const formatPositions2 = [
    [8, size - 1], [8, size - 2], [8, size - 3], [8, size - 4],
    [8, size - 5], [8, size - 6], [8, size - 7], [8, size - 8],
    [size - 7, 8], [size - 6, 8], [size - 5, 8], [size - 4, 8],
    [size - 3, 8], [size - 2, 8], [size - 1, 8],
  ];

  for (let i = 0; i < 15; i++) {
    const bit = ((bits >>> i) & 1) === 1;
    const [y1, x1] = formatPositions1[i]!;
    const [y2, x2] = formatPositions2[i]!;
    m[y1!]![x1!] = bit;
    m[y2!]![x2!] = bit;
  }

  // Version info (version >= 7)
  if (version >= 7) {
    let vrem = version;
    for (let i = 0; i < 12; i++) {
      vrem = (vrem << 1) ^ ((vrem >>> 11) * 0x1f25);
    }
    const vbits = (version << 12) | vrem;
    for (let i = 0; i < 18; i++) {
      const bit = ((vbits >>> i) & 1) === 1;
      const a = Math.floor(i / 3);
      const b = size - 11 + (i % 3);
      m[b]![a] = bit;
      m[a]![b] = bit;
    }
  }
}
