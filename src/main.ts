import './style.css';
import 'katex/dist/katex.min.css';
import katex from 'katex';
import { NTRU_PARAMS, modPos, type Polynomial } from './polynomial';
import {
  decodeMessage,
  decrypt,
  diagnoseDecryption,
  encodeMessage,
  encrypt,
  explainDecryption,
  generateKeyPair,
  type NTRUKeyPair,
} from './ntru';
import {
  type ReductionStep,
  type Vec2,
  gaussReduce,
  norm,
  randomBadBasis,
} from './lattice';

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) {
  throw new Error('Missing #app root');
}

/** Render a LaTeX string to an HTML string (inline mode), never throwing. */
function tex(latex: string, displayMode = false): string {
  return katex.renderToString(latex, { throwOnError: false, displayMode });
}

/** Typeset every [data-tex] (inline) and [data-tex-display] (block) element. */
function renderMathIn(root: ParentNode): void {
  root.querySelectorAll<HTMLElement>('[data-tex]').forEach((el) => {
    el.innerHTML = tex(el.dataset.tex ?? '');
  });
  root.querySelectorAll<HTMLElement>('[data-tex-display]').forEach((el) => {
    el.innerHTML = tex(el.dataset.texDisplay ?? '', true);
  });
}

app.innerHTML = `
  <a class="skip-link" href="#exhibit1">Skip to exhibits</a>
  <main class="lab">
    <header class="cl-hero">
      <div class="cl-hero-main">
        <h1 class="cl-hero-title">NTRU</h1>
        <p class="cl-hero-sub">1996 · the original lattice public-key cryptosystem</p>
      </div>
      <aside class="cl-hero-why" aria-label="Why it matters">
        <span class="cl-hero-why-label">WHY IT MATTERS</span>
        <p class="cl-hero-why-text">NTRU was the first practical public-key system built on hard lattice problems, hiding messages in noisy polynomial arithmetic only the private key can untangle. The same idea now underpins the post-quantum standards replacing RSA.</p>
      </aside>
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
      <p class="ring-legend" aria-hidden="true">
        <span class="swatch" style="background:#00d4ff"></span> +1
        <span class="swatch" style="background:#ff00aa"></span> −1
        <span class="swatch" style="background:#3e414b"></span> 0
        <span class="swatch" style="background:linear-gradient(90deg,#caa000,#fff0a8)"></span> mod-q magnitude (gold)
      </p>
      <p id="inspect-1" class="ring-inspect" role="status" aria-live="polite">Hover or move over a ring to inspect individual coefficients.</p>
    </section>

    <section class="card" id="exhibit2">
      <h2>Exhibit 2: Encrypt and Decrypt</h2>
      <div class="scheme-eqs">
        <div class="math-display" data-tex-display="h = p \\cdot F_q \\cdot g \\pmod q"></div>
        <div class="math-display" data-tex-display="e = r \\cdot h + m \\pmod q"></div>
        <div class="math-display" data-tex-display="f \\cdot e \\equiv p\\,r\\,g + f\\,m \\pmod q"></div>
        <div class="math-display" data-tex-display="m \\equiv F_p \\cdot (f \\cdot e \\bmod p) \\pmod p"></div>
      </div>
      <p class="assistive">The third line is the identity that makes decryption work: reduced mod p the p·r·g term vanishes, leaving f·m, which F<sub>p</sub> inverts back to m.</p>
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
      <p class="ring-legend" aria-hidden="true">
        <span class="swatch" style="background:#00d4ff"></span> +1
        <span class="swatch" style="background:#ff00aa"></span> −1
        <span class="swatch" style="background:#3e414b"></span> 0
        <span class="swatch" style="background:linear-gradient(90deg,#1f8fff,#ff5cc8)"></span> centered mod-q (cipher)
      </p>
      <p id="inspect-2" class="ring-inspect" role="status" aria-live="polite">Hover or move over a ring to inspect individual coefficients.</p>
      <p id="decode-output" class="decode" role="status" aria-live="polite"></p>
      <details id="decrypt-walkthrough" class="walkthrough">
        <summary>Show the decryption walkthrough (the algebra, step by step)</summary>
        <div id="walkthrough-body" class="walkthrough-body">
          <p class="assistive">Decrypt a message to populate this walkthrough with live values.</p>
        </div>
      </details>
      <p class="warning">Decryption failures are possible (rare, about 2^-80 for ees443ep1). This demo reports mismatches explicitly.</p>
    </section>

    <section class="card" id="exhibit3">
      <h2>Exhibit 3: The Lattice Perspective</h2>
      <p>The private key maps to a short vector in a 2N-dimensional lattice built from h. Breaking NTRU means finding that short vector. Below is the honest 2D case: Gauss–Lagrange reduction, the exact analogue of LLL, computed live step by step.</p>
      <p>Watch the basis vectors (b₁, b₂) shrink onto the same fixed lattice. The lattice points never move — only the basis describing them gets shorter and more orthogonal. The determinant stays constant because every step is unimodular.</p>
      <p>LLL is polynomial-time but coarse. BKZ is stronger and exponentially expensive in block size. For ees443ep1, attacks are estimated near 2^128 work.</p>
      <div class="controls">
        <button id="lll-step" type="button" aria-controls="lattice-canvas lll-readout">Apply Reduction Step</button>
        <button id="lll-auto" type="button" aria-controls="lattice-canvas lll-readout">Auto-Reduce</button>
        <button id="lll-new" type="button" aria-controls="lattice-canvas lll-readout">New Basis</button>
        <span id="lll-state" class="status neutral" role="status" aria-live="polite"></span>
      </div>
      <div class="ring-grid lattice-layout">
        <figure>
          <figcaption>2D lattice with current basis (b₁ cyan, b₂ magenta, shortest highlighted)</figcaption>
          <canvas id="lattice-canvas" width="520" height="360" role="img" aria-label="2D toy lattice visualization"></canvas>
        </figure>
        <pre id="lll-readout" class="log lattice-readout" role="status" aria-live="polite"></pre>
      </div>
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
<footer style="margin-top:3rem;padding:2rem 1rem;border-top:1px solid rgba(128,128,128,.25);text-align:center;font-size:.85rem;line-height:1.9;opacity:.85;font-family:ui-monospace,Menlo,Consolas,monospace">
  <div><strong>Related demos:</strong> <a href="https://systemslibrarian.github.io/crypto-lab-kyber-vault/" style="color:#35d6bb">kyber-vault</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-falcon-seal/" style="color:#35d6bb">falcon-seal</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-frodo-vault/" style="color:#35d6bb">frodo-vault</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-pq-families/" style="color:#35d6bb">pq-families</a></div>
  <div style="margin-top:.5rem"><a href="https://github.com/systemslibrarian/crypto-lab-ntru-classic" style="color:#35d6bb">Source on GitHub</a> &middot; <a href="https://crypto-lab.systemslibrarian.dev/" style="color:#35d6bb">More crypto-lab demos</a></div>
  <div style="margin-top:.75rem;opacity:.75">&ldquo;So whether you eat or drink or whatever you do, do it all for the glory of God.&rdquo; &mdash; 1 Corinthians 10:31</div>
</footer>
`;

renderMathIn(app);

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
const lllReadoutEl = document.querySelector<HTMLPreElement>('#lll-readout');
const lllStepBtn = document.querySelector<HTMLButtonElement>('#lll-step');
const lllAutoBtn = document.querySelector<HTMLButtonElement>('#lll-auto');
const lllNewBtn = document.querySelector<HTMLButtonElement>('#lll-new');
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
  !lllReadoutEl ||
  !lllStepBtn ||
  !lllAutoBtn ||
  !lllNewBtn ||
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
const lllReadout = lllReadoutEl;
const lllStep = lllStepBtn;
const lllAuto = lllAutoBtn;
const lllNew = lllNewBtn;
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

interface RingRecord {
  poly: Polynomial;
  mode: RingMode;
  label: string;
}

const ringRegistry = new Map<HTMLCanvasElement, RingRecord>();

function clearCanvas(canvas: HTMLCanvasElement): CanvasRenderingContext2D {
  const ctx = canvas.getContext('2d');
  if (!ctx) {
    throw new Error('2D canvas context unavailable');
  }
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  return ctx;
}

function drawRing(canvas: HTMLCanvasElement, poly: Polynomial, mode: RingMode, label?: string): void {
  const existing = ringRegistry.get(canvas);
  ringRegistry.set(canvas, { poly, mode, label: label ?? existing?.label ?? 'Coefficient' });

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

function describeCoeff(record: RingRecord, index: number): string {
  const value = record.poly[index];
  if (record.mode === 'private') {
    return 'hidden (secret key)';
  }
  if (record.mode === 'cipher' || record.mode === 'public') {
    return `${value} (centered ${centerCoeff(value, NTRU_PARAMS.q)})`;
  }
  return `${value}`;
}

function ringIndexAt(canvas: HTMLCanvasElement, clientX: number, clientY: number): number | null {
  const rect = canvas.getBoundingClientRect();
  const mx = (clientX - rect.left) * (canvas.width / rect.width);
  const my = (clientY - rect.top) * (canvas.height / rect.height);
  const cx = canvas.width / 2;
  const cy = canvas.height / 2;
  const dx = mx - cx;
  const dy = my - cy;
  const dist = Math.hypot(dx, dy);
  const outer = Math.min(cx, cy) - 8;
  const inner = outer - 34;
  if (dist < inner - 8 || dist > outer + 8) {
    return null;
  }
  const record = ringRegistry.get(canvas);
  const n = record ? record.poly.length : 0;
  if (n === 0) {
    return null;
  }
  // Slice i starts at angle (i/n)·2π − π/2 (top), increasing clockwise.
  let ang = Math.atan2(dy, dx) + Math.PI / 2;
  ang = ((ang % (Math.PI * 2)) + Math.PI * 2) % (Math.PI * 2);
  return Math.floor((ang / (Math.PI * 2)) * n) % n;
}

function attachRingInspector(canvas: HTMLCanvasElement): void {
  const readout = canvas.closest('section')?.querySelector<HTMLElement>('.ring-inspect');
  if (!readout) {
    return;
  }
  const idle = 'Hover or move over a ring to inspect individual coefficients.';
  const update = (clientX: number, clientY: number): void => {
    const record = ringRegistry.get(canvas);
    const index = ringIndexAt(canvas, clientX, clientY);
    if (!record || index === null) {
      readout.textContent = idle;
      return;
    }
    readout.textContent = `${record.label}: coefficient[${index}] = ${describeCoeff(record, index)}`;
  };
  canvas.addEventListener('mousemove', (event) => update(event.clientX, event.clientY));
  canvas.addEventListener('mouseleave', () => {
    readout.textContent = idle;
  });
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

const walkthroughBodyEl = document.querySelector<HTMLDivElement>('#walkthrough-body');

let keyPair: NTRUKeyPair | null = null;
let messagePoly: Polynomial | null = null;
let blindingPoly: Polynomial | null = null;
let ciphertext: Polynomial | null = null;
let originalLength = 0;

function resetWalkthrough(): void {
  if (walkthroughBodyEl) {
    walkthroughBodyEl.innerHTML =
      '<p class="assistive">Decrypt a message to populate this walkthrough with live values.</p>';
  }
}

function walkthroughStep(titleHtml: string, detail: string): string {
  return `<li><span class="wt-title">${titleHtml}</span><span class="wt-detail">${detail}</span></li>`;
}

function renderWalkthrough(): void {
  if (!walkthroughBodyEl || !keyPair || !ciphertext || !blindingPoly || !messagePoly) {
    return;
  }
  const w = explainDecryption(ciphertext, keyPair.privateKey, {
    r: blindingPoly,
    g: keyPair.g,
    m: messagePoly,
  });
  const half = Math.floor(NTRU_PARAMS.q / 2);

  const rows = [
    walkthroughStep(
      `Lift ${tex('a = \\langle f \\cdot e \\rangle')} (center-reduced mod q)`,
      `max |coefficient| = ${w.maxLiftCoeff}  ·  window is ±${half}`,
    ),
    walkthroughStep(
      `Identity check: ${tex('a \\stackrel{?}{=} \\langle p\\,r\\,g + f\\,m \\rangle \\bmod q')}`,
      w.identityHolds
        ? 'holds exactly — a = p·r·g + f·m ✓'
        : 'mismatch — ciphertext was altered, identity broken ✗',
    ),
    walkthroughStep(
      'Decryption margin before a coefficient wraps mod q',
      `${w.decryptionMargin} of ${half}  ·  smaller margin ⇒ higher failure risk`,
    ),
    walkthroughStep(
      `Strip the ${tex('p\\,r\\,g')} term: ${tex('b = a \\bmod p')}`,
      `coefficient profile: ${countCoefficients(w.aModP)}`,
    ),
    walkthroughStep(
      `Recover ${tex("m' = F_p \\cdot b \\bmod p")}`,
      `coefficient profile: ${countCoefficients(w.recovered)}`,
    ),
  ];

  walkthroughBodyEl.innerHTML = `<ol class="walkthrough-steps">${rows.join('')}</ol>`;
}

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
    blindingPoly = null;
    resetWalkthrough();
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
    blindingPoly = encrypted.blindingPoly;
    resetWalkthrough();

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
    renderWalkthrough();

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
  renderWalkthrough();
  const diagnosis = diagnoseDecryption(messagePoly, recoveredTampered);

  setStatus(
    decStatusEl,
    `Tampering demo: ${diagnosis.differingCoefficients}/${diagnosis.totalCoefficients} coefficients now differ.`,
    'warn',
  );
  decodeOutputEl.textContent = 'This demonstrates ciphertext integrity sensitivity in lattice PKE.';
});

const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

let reductionTrace: ReductionStep[] = [];
let reductionIndex = 0;
let latticeScale = 34;
let latticePoints: Vec2[] = [];
let autoTimer: number | null = null;

function drawArrow(
  ctx: CanvasRenderingContext2D,
  ox: number,
  oy: number,
  vx: number,
  vy: number,
  color: string,
  width: number,
): void {
  const tipX = ox + vx * latticeScale;
  const tipY = oy - vy * latticeScale;
  ctx.strokeStyle = color;
  ctx.fillStyle = color;
  ctx.lineWidth = width;
  ctx.beginPath();
  ctx.moveTo(ox, oy);
  ctx.lineTo(tipX, tipY);
  ctx.stroke();

  const len = Math.hypot(tipX - ox, tipY - oy);
  if (len < 6) {
    return;
  }
  const ux = (tipX - ox) / len;
  const uy = (tipY - oy) / len;
  const head = 9;
  ctx.beginPath();
  ctx.moveTo(tipX, tipY);
  ctx.lineTo(tipX - head * ux + head * 0.55 * uy, tipY - head * uy - head * 0.55 * ux);
  ctx.lineTo(tipX - head * ux - head * 0.55 * uy, tipY - head * uy + head * 0.55 * ux);
  ctx.closePath();
  ctx.fill();
}

function buildLatticePoints(b1: Vec2, b2: Vec2): Vec2[] {
  const halfW = latticeCanvasEl.width / 2 / latticeScale;
  const halfH = latticeCanvasEl.height / 2 / latticeScale;
  const shortest = Math.max(0.5, Math.min(norm(b1), norm(b2)));
  const reach = Math.hypot(halfW, halfH);
  const range = Math.min(80, Math.ceil(reach / shortest) + 2);

  const points: Vec2[] = [];
  for (let i = -range; i <= range; i += 1) {
    for (let j = -range; j <= range; j += 1) {
      const x = i * b1.x + j * b2.x;
      const y = i * b1.y + j * b2.y;
      if (Math.abs(x) <= halfW + 0.01 && Math.abs(y) <= halfH + 0.01) {
        points.push({ x, y });
      }
    }
  }
  return points;
}

function drawLattice(step: ReductionStep): void {
  const ctx = clearCanvas(latticeCanvasEl);
  const ox = latticeCanvasEl.width / 2;
  const oy = latticeCanvasEl.height / 2;

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

  for (const p of latticePoints) {
    ctx.fillStyle = '#47526a';
    ctx.beginPath();
    ctx.arc(ox + p.x * latticeScale, oy - p.y * latticeScale, 2.2, 0, Math.PI * 2);
    ctx.fill();
  }

  // Highlight the shortest vector underneath, then draw both basis vectors.
  drawArrow(ctx, ox, oy, step.shortest.x, step.shortest.y, '#9d4edd', 7);
  drawArrow(ctx, ox, oy, step.b1.x, step.b1.y, '#00d4ff', 3);
  drawArrow(ctx, ox, oy, step.b2.x, step.b2.y, '#ff00aa', 3);
}

function formatVec(v: Vec2): string {
  const round = (n: number) => (Number.isInteger(n) ? String(n) : n.toFixed(2));
  return `(${round(v.x)}, ${round(v.y)})`;
}

function renderReductionStep(): void {
  const step = reductionTrace[reductionIndex];
  drawLattice(step);

  const det = Math.abs(step.b1.x * step.b2.y - step.b1.y * step.b2.x);
  const shortNorm = Math.min(step.norms[0], step.norms[1]);
  lllReadout.textContent = [
    `Step ${reductionIndex} / ${reductionTrace.length - 1}`,
    step.description,
    '',
    `b₁ = ${formatVec(step.b1)}    ‖b₁‖ = ${step.norms[0].toFixed(3)}`,
    `b₂ = ${formatVec(step.b2)}    ‖b₂‖ = ${step.norms[1].toFixed(3)}`,
    '',
    `shortest ‖·‖ = ${shortNorm.toFixed(3)}    det = ${det.toFixed(0)} (invariant)`,
  ].join('\n');

  const atEnd = step.done || reductionIndex >= reductionTrace.length - 1;
  setStatus(
    lllStateText,
    atEnd ? 'Basis reduced: b₁ is a shortest lattice vector.' : 'Reduction in progress.',
    atEnd ? 'ok' : 'neutral',
  );
  latticeCanvasEl.setAttribute(
    'aria-label',
    `2D lattice reduction step ${reductionIndex} of ${reductionTrace.length - 1}. ${step.description}. Shortest vector norm ${shortNorm.toFixed(2)}.`,
  );

  lllStep.disabled = atEnd;
  lllStep.textContent = atEnd ? 'Reduced' : 'Apply Reduction Step';
}

function stopAuto(): void {
  if (autoTimer !== null) {
    window.clearInterval(autoTimer);
    autoTimer = null;
  }
  lllAuto.textContent = 'Auto-Reduce';
  lllAuto.setAttribute('aria-pressed', 'false');
}

function startReduction(b1: Vec2, b2: Vec2): void {
  stopAuto();
  reductionTrace = gaussReduce(b1, b2);
  reductionIndex = 0;

  let maxNorm = 1;
  for (const s of reductionTrace) {
    maxNorm = Math.max(maxNorm, s.norms[0], s.norms[1]);
  }
  const halfMin = Math.min(latticeCanvasEl.width, latticeCanvasEl.height) / 2 - 24;
  latticeScale = halfMin / maxNorm;

  const reduced = reductionTrace[reductionTrace.length - 1];
  latticePoints = buildLatticePoints(reduced.b1, reduced.b2);
  renderReductionStep();
}

lllStep.addEventListener('click', () => {
  stopAuto();
  if (reductionIndex < reductionTrace.length - 1) {
    reductionIndex += 1;
    renderReductionStep();
  }
});

lllAuto.addEventListener('click', () => {
  if (autoTimer !== null) {
    stopAuto();
    return;
  }
  if (reductionIndex >= reductionTrace.length - 1) {
    return;
  }
  if (prefersReducedMotion) {
    reductionIndex = reductionTrace.length - 1;
    renderReductionStep();
    return;
  }
  lllAuto.textContent = 'Pause';
  lllAuto.setAttribute('aria-pressed', 'true');
  autoTimer = window.setInterval(() => {
    if (reductionIndex >= reductionTrace.length - 1) {
      stopAuto();
      return;
    }
    reductionIndex += 1;
    renderReductionStep();
  }, 850);
});

lllNew.addEventListener('click', () => {
  const { b1, b2 } = randomBadBasis();
  startReduction(b1, b2);
});

startReduction({ x: 12, y: 2 }, { x: 13, y: 4 });

const empty = new Int32Array(NTRU_PARAMS.N);
drawRing(ringMessageEl, empty, 'ternary', 'Message m');
drawRing(ringBlindEl, empty, 'ternary', 'Blinding r');
drawRing(ringCipherEl, empty, 'cipher', 'Ciphertext e');
drawRing(ringRecoveredEl, empty, 'ternary', "Recovered m'");
drawRing(ringPublicEl, empty, 'public', 'Public key h');
drawRing(ringPrivateEl, empty, 'private', 'Private key f');

for (const canvas of [
  ringPublicEl,
  ringPrivateEl,
  ringMessageEl,
  ringBlindEl,
  ringCipherEl,
  ringRecoveredEl,
]) {
  attachRingInspector(canvas);
}
