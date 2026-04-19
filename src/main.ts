import './style.css';
import { NTRU_PARAMS, modPos, type Polynomial } from './polynomial';
import {
  decodeMessage,
  decrypt,
  diagnoseDecryption,
  encodeMessage,
  encrypt,
  generateKeyPair,
  type NTRUKeyPair,
} from './ntru';

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) {
  throw new Error('Missing #app root');
}

app.innerHTML = `
  <a class="skip-link" href="#exhibit1">Skip to exhibits</a>
  <main class="lab">
    <header class="hero">
      <p class="eyebrow">crypto-lab-ntru-classic</p>
      <h1>NTRU (1996): The Original Lattice Cryptosystem</h1>
      <p class="lede">EESS#1 v3.3 ees443ep1 with N=443, p=3, q=2048. No external crypto libraries.</p>
    </header>

    <section class="card" id="exhibit1">
      <h2>Exhibit 1: Probabilistic Key Generation</h2>
      <p>Key generation retries until f is invertible mod 3 and mod 2048. This probabilistic loop is expected behavior.</p>
      <div class="controls">
        <button id="generate-keypair" type="button" aria-controls="keygen-log ring-public ring-private">Generate Keypair</button>
        <span id="keygen-summary" class="status neutral" role="status" aria-live="polite">No keypair generated yet.</span>
      </div>
      <pre id="keygen-log" class="log" aria-live="polite"></pre>
      <div class="ring-grid">
        <figure>
          <figcaption>Public key h (shared, gold)</figcaption>
          <canvas id="ring-public" width="330" height="330" role="img" aria-label="Public key ring visualization"></canvas>
        </figure>
        <figure>
          <figcaption>Private key f (red, censored band)</figcaption>
          <canvas id="ring-private" width="330" height="330" role="img" aria-label="Private key ring visualization"></canvas>
        </figure>
      </div>
    </section>

    <section class="card" id="exhibit2">
      <h2>Exhibit 2: Encrypt and Decrypt</h2>
      <label for="message-input">Message</label>
      <input id="message-input" value="Hello, NTRU 1996!" maxlength="73" aria-describedby="message-help" />
      <p id="message-help" class="assistive">Maximum 73 bytes for ees443ep1 encoding in this demo.</p>
      <p id="message-meta" class="assistive" role="status" aria-live="polite"></p>
      <div class="controls">
        <button id="encrypt-message" type="button" aria-controls="ring-message ring-blind ring-cipher">Encrypt</button>
        <button id="decrypt-message" type="button" aria-controls="ring-recovered" disabled>Decrypt</button>
        <button id="tamper-ciphertext" type="button" aria-controls="ring-cipher ring-recovered" disabled>Tamper Ciphertext</button>
      </div>
      <p id="enc-status" class="status neutral" role="status" aria-live="polite">Ready.</p>
      <p id="dec-status" class="status neutral" role="status" aria-live="polite">Decryption pending.</p>
      <div class="ring-grid">
        <figure>
          <figcaption>Message m (ternary ring)</figcaption>
          <canvas id="ring-message" width="330" height="330" role="img" aria-label="Message polynomial ring"></canvas>
        </figure>
        <figure>
          <figcaption>Blinding r (ternary ring)</figcaption>
          <canvas id="ring-blind" width="330" height="330" role="img" aria-label="Blinding polynomial ring"></canvas>
        </figure>
        <figure>
          <figcaption>Ciphertext e (mod q ring)</figcaption>
          <canvas id="ring-cipher" width="330" height="330" role="img" aria-label="Ciphertext polynomial ring"></canvas>
        </figure>
        <figure>
          <figcaption>Recovered m' (ternary ring)</figcaption>
          <canvas id="ring-recovered" width="330" height="330" role="img" aria-label="Recovered message polynomial ring"></canvas>
        </figure>
      </div>
      <p id="decode-output" class="decode" role="status" aria-live="polite"></p>
      <p class="warning">Decryption failures are possible (rare, about 2^-80 for ees443ep1). This demo reports mismatches explicitly.</p>
    </section>

    <section class="card" id="exhibit3">
      <h2>Exhibit 3: The Lattice Perspective</h2>
      <p>The private key maps to a short vector in a 2N-dimensional lattice built from h. Breaking NTRU means finding that short vector.</p>
      <p>LLL is polynomial-time but coarse. BKZ is stronger and exponentially expensive in block size. For ees443ep1, attacks are estimated near 2^128 work.</p>
      <div class="controls">
        <button id="lll-step" type="button">Apply LLL Step</button>
        <span id="lll-state" class="status neutral" role="status" aria-live="polite"></span>
      </div>
      <canvas id="lattice-canvas" width="520" height="360" role="img" aria-label="2D toy lattice visualization"></canvas>
    </section>

    <section class="card" id="exhibit4">
      <h2>Exhibit 4: NTRU Classic vs Kyber</h2>
      <div class="table-wrap">
      <table>
        <caption>Comparison of NTRU Classic and ML-KEM-768</caption>
        <thead><tr><th scope="col">Property</th><th scope="col">NTRU Classic (1996)</th><th scope="col">ML-KEM-768 (2024)</th></tr></thead>
        <tbody>
          <tr><td>Designer(s)</td><td>Hoffstein, Pipher, Silverman</td><td>Avanzi, Bos, Ducas, Kiltz et al.</td></tr>
          <tr><td>Ring</td><td>Z[X]/(X^N - 1)</td><td>Z_q[X]/(X^n + 1), n=256</td></tr>
          <tr><td>Parameters</td><td>N=443, q=2048</td><td>n=256, q=3329, rank 3</td></tr>
          <tr><td>Public key size</td><td>~609 bytes</td><td>1184 bytes</td></tr>
          <tr><td>Ciphertext size</td><td>~609 bytes</td><td>1088 bytes</td></tr>
          <tr><td>Security assumption</td><td>NTRU-specific</td><td>MLWE + MSIS</td></tr>
          <tr><td>Decryption failures</td><td>~2^-80</td><td>~2^-164</td></tr>
          <tr><td>NIST status</td><td>2020 finalist</td><td>Standardized (FIPS 203)</td></tr>
          <tr><td>Patent status</td><td>Expired 2017</td><td>Patent-free</td></tr>
        </tbody>
      </table>
      </div>
      <p class="lineage">NTRU (1996) -> Ring-LWE (2010) -> Kyber / ML-KEM (2024)</p>
    </section>

    <section class="card" id="exhibit5">
      <h2>Exhibit 5: Historical Impact and Patent Story</h2>
      <ul class="timeline">
        <li>1996: NTRU invented at Brown University</li>
        <li>1997: US Patent 6,081,597 filed</li>
        <li>1998: ANTS-III publication</li>
        <li>2009: IEEE P1363.1 standard</li>
        <li>2011: X9.98 financial services standard</li>
        <li>2017: Patent expires globally</li>
        <li>2020: NTRU is a NIST PQC finalist</li>
        <li>2024: ML-KEM standardized as FIPS 203</li>
      </ul>
      <p>Kyber won due to stronger reductions, NTT-friendly arithmetic, and immediate patent clarity. NTRU remains foundational for understanding lattice cryptography.</p>
      <p class="cross-links">Related labs: crypto-lab-kyber-vault, crypto-lab-dilithium-seal, crypto-lab-falcon-seal, crypto-lab-lll-break, crypto-lab-lattice-fault, crypto-lab-hybrid-wire, crypto-lab-harvest-vault.</p>
    </section>
  </main>
`;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const keyLog = document.querySelector<HTMLPreElement>('#keygen-log');
const keySummary = document.querySelector<HTMLSpanElement>('#keygen-summary');
const generateButton = document.querySelector<HTMLButtonElement>('#generate-keypair');
const encryptButton = document.querySelector<HTMLButtonElement>('#encrypt-message');
const decryptButton = document.querySelector<HTMLButtonElement>('#decrypt-message');
const tamperButton = document.querySelector<HTMLButtonElement>('#tamper-ciphertext');
const encStatus = document.querySelector<HTMLParagraphElement>('#enc-status');
const decStatus = document.querySelector<HTMLParagraphElement>('#dec-status');
const decodeOutput = document.querySelector<HTMLParagraphElement>('#decode-output');
const messageInput = document.querySelector<HTMLInputElement>('#message-input');
const messageMeta = document.querySelector<HTMLParagraphElement>('#message-meta');

const ringPublic = document.querySelector<HTMLCanvasElement>('#ring-public');
const ringPrivate = document.querySelector<HTMLCanvasElement>('#ring-private');
const ringMessage = document.querySelector<HTMLCanvasElement>('#ring-message');
const ringBlind = document.querySelector<HTMLCanvasElement>('#ring-blind');
const ringCipher = document.querySelector<HTMLCanvasElement>('#ring-cipher');
const ringRecovered = document.querySelector<HTMLCanvasElement>('#ring-recovered');

const lllStateEl = document.querySelector<HTMLSpanElement>('#lll-state');
const latticeCanvas = document.querySelector<HTMLCanvasElement>('#lattice-canvas');

if (
  !keyLog ||
  !keySummary ||
  !generateButton ||
  !encryptButton ||
  !decryptButton ||
  !tamperButton ||
  !encStatus ||
  !decStatus ||
  !decodeOutput ||
  !messageInput ||
  !messageMeta ||
  !ringPublic ||
  !ringPrivate ||
  !ringMessage ||
  !ringBlind ||
  !ringCipher ||
  !ringRecovered ||
  !lllStateEl ||
  !latticeCanvas
) {
  throw new Error('UI initialization failed');
}

const keyLogEl = keyLog;
const keySummaryEl = keySummary;
const generateButtonEl = generateButton;
const encryptButtonEl = encryptButton;
const decryptButtonEl = decryptButton;
const tamperButtonEl = tamperButton;
const encStatusEl = encStatus;
const decStatusEl = decStatus;
const decodeOutputEl = decodeOutput;
const messageInputEl = messageInput;
const messageMetaEl = messageMeta;
const ringPublicEl = ringPublic;
const ringPrivateEl = ringPrivate;
const ringMessageEl = ringMessage;
const ringBlindEl = ringBlind;
const ringCipherEl = ringCipher;
const ringRecoveredEl = ringRecovered;
const lllStateText = lllStateEl;
const latticeCanvasEl = latticeCanvas;
const maxBytes = Math.floor(NTRU_PARAMS.N / 6);

messageInputEl.maxLength = maxBytes;
updateMessageMeta(encoder.encode(messageInputEl.value).length);

messageInputEl.addEventListener('input', () => {
  const bytes = encoder.encode(messageInputEl.value);
  updateMessageMeta(bytes.length);
  if (bytes.length > maxBytes) {
    messageInputEl.setAttribute('aria-invalid', 'true');
  } else {
    messageInputEl.removeAttribute('aria-invalid');
  }
});

type RingMode = 'ternary' | 'cipher' | 'public' | 'private';

function clearCanvas(canvas: HTMLCanvasElement): CanvasRenderingContext2D {
  const ctx = canvas.getContext('2d');
  if (!ctx) {
    throw new Error('2D canvas context unavailable');
  }
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  return ctx;
}

function drawRing(canvas: HTMLCanvasElement, poly: Polynomial, mode: RingMode): void {
  const ctx = clearCanvas(canvas);
  const cx = canvas.width / 2;
  const cy = canvas.height / 2;
  const outer = Math.min(cx, cy) - 8;
  const inner = outer - 34;
  const n = poly.length;

  ctx.beginPath();
  ctx.arc(cx, cy, outer + 5, 0, Math.PI * 2);
  ctx.fillStyle = '#101521';
  ctx.fill();

  for (let i = 0; i < n; i += 1) {
    const start = (i / n) * Math.PI * 2 - Math.PI / 2;
    const end = ((i + 1) / n) * Math.PI * 2 - Math.PI / 2;
    const coeff = poly[i];

    let color = '#3e414b';
    if (mode === 'ternary') {
      color = coeff === 1 ? '#00d4ff' : coeff === -1 ? '#ff00aa' : '#3e414b';
    } else if (mode === 'public') {
      const centered = centerCoeff(coeff, NTRU_PARAMS.q);
      const intensity = Math.min(100, Math.abs(centered) / 7);
      color = `hsl(47 100% ${40 + intensity * 0.35}%)`;
    } else if (mode === 'private') {
      color = coeff === 1 || coeff === -1 ? '#ff3366' : '#3e414b';
    } else {
      const centered = centerCoeff(coeff, NTRU_PARAMS.q);
      const base = centered >= 0 ? 190 : 320;
      const lum = 34 + Math.min(40, Math.abs(centered) / 30);
      color = `hsl(${base} 93% ${lum}%)`;
    }

    ctx.beginPath();
    ctx.arc(cx, cy, outer, start, end);
    ctx.arc(cx, cy, inner, end, start, true);
    ctx.closePath();
    ctx.fillStyle = color;
    ctx.fill();
  }

  if (mode === 'private') {
    ctx.fillStyle = 'rgba(8, 11, 18, 0.86)';
    ctx.fillRect(50, cy - 18, canvas.width - 100, 36);
    ctx.fillStyle = '#ffacbe';
    ctx.font = '600 13px "JetBrains Mono", monospace';
    ctx.textAlign = 'center';
    ctx.fillText('private key hidden', cx, cy + 5);
  }
}

function centerCoeff(value: number, m: number): number {
  const half = m / 2;
  const reduced = modPos(value, m);
  return reduced > half ? reduced - m : reduced;
}

function countCoefficients(poly: Polynomial): string {
  let plus = 0;
  let minus = 0;
  let zero = 0;

  for (let i = 0; i < poly.length; i += 1) {
    if (poly[i] === 1) {
      plus += 1;
    } else if (poly[i] === -1) {
      minus += 1;
    } else if (poly[i] === 0) {
      zero += 1;
    }
  }

  return `${plus} x +1, ${minus} x -1, ${zero} x 0`;
}

function setStatus(el: HTMLElement, text: string, kind: 'neutral' | 'ok' | 'warn'): void {
  el.textContent = text;
  el.className = `status ${kind}`;

  if (kind === 'warn') {
    el.setAttribute('role', 'alert');
    el.setAttribute('aria-live', 'assertive');
  } else {
    el.setAttribute('role', 'status');
    el.setAttribute('aria-live', 'polite');
  }
}

function setButtonBusy(button: HTMLButtonElement, busy: boolean, idleLabel: string): void {
  button.disabled = busy;
  button.setAttribute('aria-busy', String(busy));
  button.textContent = busy ? `${idleLabel}...` : idleLabel;
}

function updateMessageMeta(bytesLength: number): void {
  const remaining = maxBytes - bytesLength;
  messageMetaEl.textContent = `${bytesLength}/${maxBytes} bytes used (${remaining} remaining).`;
}

let keyPair: NTRUKeyPair | null = null;
let messagePoly: Polynomial | null = null;
let ciphertext: Polynomial | null = null;
let originalLength = 0;

generateButtonEl.addEventListener('click', () => {
    setButtonBusy(generateButtonEl, true, 'Generate Keypair');
    const lines: string[] = [];
    let sawFailure = false;

    keyPair = generateKeyPair((attempt, reason) => {
      const failed = reason.includes('not invertible');
      if (failed) {
        sawFailure = true;
      }
      lines.push(`Attempt ${attempt}: ${reason}${failed ? ' ✗' : ' ✓'}`);
    });

    lines.unshift('Parameters: N=443, p=3, q=2048, df=143, dg=143, dr=143');
    if (!sawFailure) {
      lines.push('No failure in this run. Non-invertible f events are expected and appear on other runs.');
    }

    keyLogEl.textContent = lines.join('\n');
    setStatus(
      keySummaryEl,
      `Keypair ready in ${keyPair.generationAttempts} attempt(s).`,
      'ok',
    );
    setStatus(decStatusEl, 'Ciphertext invalidated after key regeneration. Re-encrypt to continue.', 'neutral');
    decryptButtonEl.disabled = true;
    tamperButtonEl.disabled = true;
    ciphertext = null;
    messagePoly = null;
    decodeOutputEl.textContent = '';

    drawRing(ringPublicEl, keyPair.publicKey, 'public');
    drawRing(ringPrivateEl, keyPair.privateKey.f, 'private');
    setButtonBusy(generateButtonEl, false, 'Generate Keypair');
  });

encryptButtonEl.addEventListener('click', () => {
    if (!keyPair) {
      setStatus(encStatusEl, 'Generate a keypair first.', 'warn');
      return;
    }

    const bytes = encoder.encode(messageInputEl.value);
    updateMessageMeta(bytes.length);
    if (bytes.length > maxBytes) {
      messageInputEl.setAttribute('aria-invalid', 'true');
      setStatus(encStatusEl, `Message is too long for N=${NTRU_PARAMS.N}. Max ${maxBytes} bytes.`, 'warn');
      return;
    }
    messageInputEl.removeAttribute('aria-invalid');
    try {
      messagePoly = encodeMessage(bytes, NTRU_PARAMS.N);
    } catch (error) {
      setStatus(encStatusEl, `Encoding failed: ${(error as Error).message}`, 'warn');
      return;
    }

    originalLength = bytes.length;
    const encrypted = encrypt(messagePoly, keyPair.publicKey);
    ciphertext = encrypted.ciphertext;

    drawRing(ringMessageEl, messagePoly, 'ternary');
    drawRing(ringBlindEl, encrypted.blindingPoly, 'ternary');
    drawRing(ringCipherEl, ciphertext, 'cipher');

    setStatus(
      encStatusEl,
      `Encoded ${bytes.length} bytes into ${bytes.length * 6} ternary coefficients with ${NTRU_PARAMS.N - bytes.length * 6} zero padding.`,
      'ok',
    );
    setStatus(decStatusEl, 'Ciphertext ready. Click decrypt.', 'neutral');
    decryptButtonEl.disabled = false;
    tamperButtonEl.disabled = false;
    decodeOutputEl.textContent = `Message coefficient profile: ${countCoefficients(messagePoly)}`;
  });

decryptButtonEl.addEventListener('click', () => {
    if (!keyPair || !ciphertext || !messagePoly) {
      setStatus(decStatusEl, 'Encrypt first so there is ciphertext to decrypt.', 'warn');
      return;
    }

    const recovered = decrypt(ciphertext, keyPair.privateKey);
    drawRing(ringRecoveredEl, recovered, 'ternary');

    const diagnosis = diagnoseDecryption(messagePoly, recovered);
    if (diagnosis.matches) {
      const decoded = decodeMessage(recovered, originalLength);
      setStatus(decStatusEl, 'Valid decryption: m recovered exactly.', 'ok');
      decodeOutputEl.textContent = `Recovered text: ${decoder.decode(decoded)}`;
    } else {
      setStatus(
        decStatusEl,
        `Decryption mismatch detected: ${diagnosis.differingCoefficients}/${diagnosis.totalCoefficients} coefficients differ.`,
        'warn',
      );
      decodeOutputEl.textContent = 'Warning: rare decryption failure or tampering event observed.';
    }
  });

tamperButtonEl.addEventListener('click', () => {
  if (!keyPair || !ciphertext || !messagePoly) {
    setStatus(decStatusEl, 'Encrypt first so ciphertext exists before tampering.', 'warn');
    return;
  }

  const tampered = new Int32Array(ciphertext);
  tampered[0] = modPos(tampered[0] + 777, NTRU_PARAMS.q);
  tampered[5] = modPos(tampered[5] + 999, NTRU_PARAMS.q);
  ciphertext = tampered;

  drawRing(ringCipherEl, ciphertext, 'cipher');

  const recoveredTampered = decrypt(ciphertext, keyPair.privateKey);
  drawRing(ringRecoveredEl, recoveredTampered, 'ternary');
  const diagnosis = diagnoseDecryption(messagePoly, recoveredTampered);

  setStatus(
    decStatusEl,
    `Tampering demo: ${diagnosis.differingCoefficients}/${diagnosis.totalCoefficients} coefficients now differ.`,
    'warn',
  );
  decodeOutputEl.textContent = 'This demonstrates ciphertext integrity sensitivity in lattice PKE.';
});

interface LatticeState {
  label: string;
  b1: [number, number];
  b2: [number, number];
}

const latticeStates: LatticeState[] = [
  { label: 'Bad basis: long, near-parallel vectors', b1: [6, 1], b2: [5.2, 0.8] },
  { label: 'Size reduction: b2 <- b2 - b1', b1: [6, 1], b2: [-0.8, -0.2] },
  { label: 'Swap and reduce: shorter, more orthogonal', b1: [-0.8, -0.2], b2: [1.2, -0.4] },
];

let latticeStep = 0;

function drawLattice(state: LatticeState): void {
  const ctx = clearCanvas(latticeCanvasEl);
  const ox = latticeCanvasEl.width / 2;
  const oy = latticeCanvasEl.height / 2;
  const scale = 34;

  ctx.fillStyle = '#0b0f18';
  ctx.fillRect(0, 0, latticeCanvasEl.width, latticeCanvasEl.height);

  ctx.strokeStyle = '#2b3241';
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(0, oy);
  ctx.lineTo(latticeCanvasEl.width, oy);
  ctx.moveTo(ox, 0);
  ctx.lineTo(ox, latticeCanvasEl.height);
  ctx.stroke();

  for (let i = -4; i <= 4; i += 1) {
    for (let j = -4; j <= 4; j += 1) {
      const x = ox + scale * (i * state.b1[0] + j * state.b2[0]);
      const y = oy - scale * (i * state.b1[1] + j * state.b2[1]);
      if (x < 0 || y < 0 || x > latticeCanvasEl.width || y > latticeCanvasEl.height) {
        continue;
      }
      ctx.fillStyle = '#47526a';
      ctx.beginPath();
      ctx.arc(x, y, 2.2, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  const vectors: [number, number, string][] = [
    [state.b1[0], state.b1[1], '#00d4ff'],
    [state.b2[0], state.b2[1], '#ff00aa'],
  ];

  let shortest: [number, number] = [state.b1[0], state.b1[1]];
  let shortestNorm = state.b1[0] ** 2 + state.b1[1] ** 2;
  const candidate = [state.b2[0], state.b2[1]] as [number, number];
  const norm2 = candidate[0] ** 2 + candidate[1] ** 2;
  if (norm2 < shortestNorm) {
    shortest = candidate;
    shortestNorm = norm2;
  }

  for (const [vx, vy, color] of vectors) {
    ctx.strokeStyle = color;
    ctx.lineWidth = 3;
    ctx.beginPath();
    ctx.moveTo(ox, oy);
    ctx.lineTo(ox + vx * scale, oy - vy * scale);
    ctx.stroke();
  }

  ctx.strokeStyle = '#9d4edd';
  ctx.lineWidth = 4;
  ctx.beginPath();
  ctx.moveTo(ox, oy);
  ctx.lineTo(ox + shortest[0] * scale, oy - shortest[1] * scale);
  ctx.stroke();

  lllStateText.textContent = state.label;
}

drawLattice(latticeStates[latticeStep]);

document.querySelector<HTMLButtonElement>('#lll-step')?.addEventListener('click', () => {
  latticeStep = (latticeStep + 1) % latticeStates.length;
  drawLattice(latticeStates[latticeStep]);
});

const empty = new Int32Array(NTRU_PARAMS.N);
drawRing(ringMessageEl, empty, 'ternary');
drawRing(ringBlindEl, empty, 'ternary');
drawRing(ringCipherEl, empty, 'cipher');
drawRing(ringRecoveredEl, empty, 'ternary');
drawRing(ringPublicEl, empty, 'public');
drawRing(ringPrivateEl, empty, 'private');
