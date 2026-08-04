import { expect, test as base, type Locator, type Page } from '@playwright/test';

/**
 * Functional gate on the claims this lab makes on screen.
 *
 * The a11y suite gates accessibility and the Vitest suites gate the NTRU
 * vectors; neither checks that the *page* tells the truth about the run it just
 * performed. This suite drives the real controls and re-derives every headline
 * from the page's own numbers: the encoding counts against N, the decryption
 * margin against ±q/2, the walkthrough against the pipeline readout, the 2D
 * reduction's determinant against its own invariance claim, and the lattice
 * attack's "= (p·g ‖ f), rotated by k" against the secret it printed.
 */

const N = 443;
const Q = 2048;
const HALF_Q = Q / 2;
const MAX_BYTES = Math.floor(N / 6); // 73

const test = base.extend<{ pageErrors: string[] }>({
  pageErrors: [
    async ({ page }, use) => {
      const errors: string[] = [];
      page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`));
      page.on('console', (message) => {
        if (message.type() === 'error') errors.push(`console.error: ${message.text()}`);
      });
      await use(errors);
      expect(errors, 'uncaught page errors').toEqual([]);
    },
    { auto: true },
  ],
});

async function open(page: Page): Promise<void> {
  await page.goto('.');
  await expect(page.locator('#message-input')).toBeVisible();
}

async function flat(locator: Locator): Promise<string> {
  return (await locator.innerText()).replace(/\s+/g, ' ').trim();
}

function grab(source: string, pattern: RegExp): RegExpMatchArray {
  const match = source.match(pattern);
  expect(match, `expected ${pattern} in: ${source}`).not.toBeNull();
  return match as RegExpMatchArray;
}

/** The four progressive-reveal equation badges, in document order. */
const badges = (page: Page): Locator => page.locator('.eq-badge');

/** "a x +1, b x -1, c x 0" → the three counts. */
function profile(text: string): { plus: number; minus: number; zero: number } {
  const m = grab(text, /(\d+) x \+1, (\d+) x -1, (\d+) x 0/);
  return { plus: Number(m[1]), minus: Number(m[2]), zero: Number(m[3]) };
}

async function generateKeypair(page: Page): Promise<void> {
  await page.locator('#generate-keypair').click();
  await expect(page.locator('#keygen-summary')).toContainText('Keypair ready', { timeout: 60_000 });
}

async function encrypt(page: Page): Promise<void> {
  await page.locator('#encrypt-message').click();
  await expect(page.locator('#enc-status')).toContainText('Encoded', { timeout: 60_000 });
}

async function decrypt(page: Page): Promise<void> {
  await page.locator('#decrypt-message').click();
  await expect(page.locator('#dec-status')).toContainText(/Valid decryption|mismatch/, {
    timeout: 60_000,
  });
}

// ---------------------------------------------------------------------------
// Exhibit 1 — key generation
// ---------------------------------------------------------------------------

test('keygen: the summary counts the attempts the log printed, and unlocks only h', async ({
  page,
}) => {
  await open(page);

  await expect(page.locator('#keygen-summary')).toHaveText('No keypair generated yet.');
  await expect(badges(page)).toHaveText([
    'Needs a keypair',
    'Needs Encrypt',
    'Needs Decrypt',
    'Needs Decrypt',
  ]);

  await generateKeypair(page);

  const attempts = Number(
    grab(await flat(page.locator('#keygen-summary')), /Keypair ready in (\d+) attempt\(s\)/)[1],
  );
  expect(attempts).toBeGreaterThanOrEqual(1);

  const log = await flat(page.locator('#keygen-log'));
  // The parameter line is the set the README documents.
  expect(log).toContain('Parameters: N=443, p=3, q=2048, df=143, dg=143, dr=143');
  expect(log).toContain('ePrint 2015/708');
  expect(log).toContain('not EESS#1 ees443ep1');

  // The log's highest attempt number is the number the summary claims.
  const attemptNumbers = [...log.matchAll(/Attempt (\d+):/g)].map((m) => Number(m[1]));
  expect(attemptNumbers.length).toBeGreaterThan(0);
  expect(Math.max(...attemptNumbers)).toBe(attempts);
  // The final attempt completed; any earlier attempt was discarded for a stated
  // reason, and the run says which case it was.
  expect(log).toContain('Attempt ' + attempts + ': Key generation complete ✓');
  if (attempts === 1) {
    expect(log).toContain('No failure in this run');
  } else {
    expect(log).toContain('not invertible ✗');
  }

  // Only the h equation unlocks: nothing has been encrypted yet.
  await expect(badges(page)).toHaveText([
    'h is on screen ✓',
    'Needs Encrypt',
    'Needs Decrypt',
    'Needs Decrypt',
  ]);
});

// ---------------------------------------------------------------------------
// Exhibit 2 — encrypt / decrypt
// ---------------------------------------------------------------------------

test('encode: the byte budget and the coefficient counts add up to N', async ({ page }) => {
  await open(page);
  await generateKeypair(page);

  const message = 'Hé, NTRU 1996!'; // é is 2 bytes: the counter must be bytes, not chars
  const byteLength = new TextEncoder().encode(message).length;
  await page.locator('#message-input').fill(message);

  const meta = grab(
    await flat(page.locator('#message-meta')),
    /(\d+)\/(\d+) bytes used \((\d+) remaining\)/,
  );
  expect(Number(meta[1])).toBe(byteLength);
  expect(Number(meta[2])).toBe(MAX_BYTES);
  // Parts sum to the whole.
  expect(Number(meta[1]) + Number(meta[3])).toBe(MAX_BYTES);

  // The page states the budget in three places — the help text, the live
  // counter, and the field's own maxlength. The help text is authored by hand
  // while the other two are computed, so they must be checked against each
  // other rather than each against a constant.
  const help = grab(
    await flat(page.locator('#message-help')),
    /Maximum (\d+) bytes for this demo's N=(\d+) encoding/,
  );
  expect(Number(help[1])).toBe(Number(meta[2]));
  expect(Number(help[2])).toBe(N);
  await expect(page.locator('#message-input')).toHaveAttribute('maxlength', meta[2]!);

  await encrypt(page);

  const status = grab(
    await flat(page.locator('#enc-status')),
    /Encoded (\d+) bytes into (\d+) ternary coefficients with (\d+) zero padding/,
  );
  expect(Number(status[1])).toBe(byteLength);
  // Six balanced-base-3 slots per byte, and the coefficients plus the padding
  // fill the ring exactly.
  expect(Number(status[2])).toBe(byteLength * 6);
  expect(Number(status[2]) + Number(status[3])).toBe(N);

  const counts = profile(await flat(page.locator('#decode-output')));
  expect(counts.plus + counts.minus + counts.zero).toBe(N);
  // A ternary encoding of a real message has non-zero coefficients, and at most
  // one per encoded slot.
  expect(counts.plus + counts.minus).toBeGreaterThan(0);
  expect(counts.plus + counts.minus).toBeLessThanOrEqual(byteLength * 6);
});

test('decrypt: the message round-trips and the walkthrough agrees with the pipeline', async ({
  page,
}) => {
  await open(page);
  await generateKeypair(page);

  const message = 'Hé, NTRU 1996!';
  await page.locator('#message-input').fill(message);
  await encrypt(page);
  const encoded = profile(await flat(page.locator('#decode-output')));

  await expect(badges(page)).toHaveText([
    'h is on screen ✓',
    'e is on screen ✓',
    'Needs Decrypt',
    'Needs Decrypt',
  ]);

  await decrypt(page);

  // The headline verdict, and the actual text it recovered.
  await expect(page.locator('#dec-status')).toHaveText('Valid decryption: m recovered exactly.');
  await expect(page.locator('#dec-status')).toHaveClass(/status ok/);
  expect(await flat(page.locator('#decode-output'))).toBe(`Recovered text: ${message}`);

  await expect(badges(page)).toHaveText([
    'h is on screen ✓',
    'e is on screen ✓',
    'verified live ✓',
    "m' recovered ✓",
  ]);

  await page.locator('#decrypt-walkthrough').evaluate((d) => ((d as HTMLDetailsElement).open = true));
  const walk = await flat(page.locator('#walkthrough-body'));

  // The identity that makes decryption work must be checked, not asserted.
  expect(walk).toContain('holds exactly — a = p·r·g + f·m ✓');
  expect(walk).not.toContain('identity broken');

  const lift = Number(grab(walk, /max \|coefficient\| = (\d+) · window is ±(\d+)/)[1]);
  const window = Number(grab(walk, /max \|coefficient\| = \d+ · window is ±(\d+)/)[1]);
  const margin = Number(grab(walk, /(\d+) of (\d+) · smaller margin/)[1]);
  expect(window).toBe(HALF_Q);
  // Margin is what is left of the ±q/2 window: the parts sum to the whole.
  expect(lift + margin).toBe(HALF_Q);
  expect(lift, 'an honest decryption stays well inside the window').toBeLessThan(HALF_Q);

  // The pipeline readout must report the same two numbers.
  const pipe = grab(
    await flat(page.locator('#pipe-margin')),
    /largest \|coeff\| = (\d+) · margin to wrap = (\d+) of (\d+)/,
  );
  expect(Number(pipe[1])).toBe(lift);
  expect(Number(pipe[2])).toBe(margin);
  expect(Number(pipe[3])).toBe(HALF_Q);

  // The recovered polynomial's coefficient profile is the encoded one, exactly.
  const recovered = profile(grab(walk, /Recover .*?coefficient profile: (\d+ x \+1, \d+ x -1, \d+ x 0)/)[1]!);
  expect(recovered).toEqual(encoded);
  // The intermediate b = a mod p is dense — that is the p·r·g layer being
  // stripped, not the message.
  const stripped = profile(grab(walk, /Strip the .*?coefficient profile: (\d+ x \+1, \d+ x -1, \d+ x 0)/)[1]!);
  expect(stripped.plus + stripped.minus + stripped.zero).toBe(N);
  expect(stripped.zero).toBeLessThan(recovered.zero);

  // A verdict must not outlive the ciphertext it was computed from. Encrypting
  // a new message retracts the whole decryption result — the headline, the two
  // equation badges, the walkthrough and the pipeline margin — rather than
  // leaving last run's "verified live" beside a ciphertext it never saw.
  await page.locator('#message-input').fill('a different plaintext');
  await encrypt(page);
  await expect(page.locator('#dec-status')).toHaveText('Ciphertext ready. Click decrypt.');
  await expect(page.locator('#dec-status')).toHaveClass(/status neutral/);
  await expect(badges(page)).toHaveText([
    'h is on screen ✓',
    'e is on screen ✓',
    'Needs Decrypt',
    'Needs Decrypt',
  ]);
  await expect(page.locator('#walkthrough-body')).toHaveText(
    'Decrypt a message to populate this walkthrough with live values.',
  );
  await expect(page.locator('#pipe-margin')).toHaveText('');
  expect(await flat(page.locator('#decode-output'))).not.toContain('Recovered text:');

  // And decrypting again produces a verdict about the new message, not the old.
  await decrypt(page);
  await expect(page.locator('#decode-output')).toHaveText('Recovered text: a different plaintext');
});

test('tamper: a modified ciphertext breaks the identity and is reported, and re-encrypting recovers', async ({
  page,
}) => {
  await open(page);
  await generateKeypair(page);
  await page.locator('#message-input').fill('Hé, NTRU 1996!');
  await encrypt(page);
  await decrypt(page);

  // The honest run's headroom, to compare the tampered one against.
  const honestLift = Number(
    grab(await flat(page.locator('#pipe-margin')), /largest \|coeff\| = (\d+)/)[1],
  );

  await page.locator('#tamper-ciphertext').click();
  await expect(page.locator('#dec-status')).toContainText('Tampering demo');
  await expect(page.locator('#dec-status')).toHaveClass(/status warn/);

  const diff = grab(
    await flat(page.locator('#dec-status')),
    /Tampering demo: (\d+)\/(\d+) coefficients now differ/,
  );
  expect(Number(diff[2])).toBe(N);
  expect(Number(diff[1]), 'tampering must actually corrupt the recovery').toBeGreaterThan(0);
  expect(Number(diff[1])).toBeLessThanOrEqual(N);
  expect(await flat(page.locator('#decode-output'))).toContain('ciphertext integrity sensitivity');

  await page.locator('#decrypt-walkthrough').evaluate((d) => ((d as HTMLDetailsElement).open = true));
  const walk = await flat(page.locator('#walkthrough-body'));
  // The failure is diagnosed by the identity check, and the margin collapses.
  expect(walk).toContain('mismatch — ciphertext was altered, identity broken ✗');
  expect(walk).not.toContain('holds exactly');
  const lift = Number(grab(walk, /max \|coefficient\| = (\d+) · window is ±\d+/)[1]);
  const margin = Number(grab(walk, /(\d+) of \d+ · smaller margin/)[1]);
  expect(lift + margin).toBe(HALF_Q);
  // The tampered lift is pushed to the edge of the ±q/2 window, far past the
  // headroom the honest ciphertext had.
  expect(lift, 'tampering must blow the decryption margin').toBeGreaterThan(honestLift);
  expect(lift).toBeGreaterThan(HALF_Q * 0.9);

  // Re-encrypting the same message restores a clean decryption.
  await encrypt(page);
  await decrypt(page);
  await expect(page.locator('#dec-status')).toHaveText('Valid decryption: m recovered exactly.');
  await expect(page.locator('#decode-output')).toHaveText('Recovered text: Hé, NTRU 1996!');
});

test('preconditions: each control refuses in order and says what is missing', async ({ page }) => {
  await open(page);

  // Encrypt before a keypair exists.
  await expect(page.locator('#decrypt-message')).toBeDisabled();
  await expect(page.locator('#tamper-ciphertext')).toBeDisabled();
  await page.locator('#encrypt-message').click();
  await expect(page.locator('#enc-status')).toHaveText('Generate a keypair first.');
  await expect(page.locator('#enc-status')).toHaveClass(/status warn/);

  await generateKeypair(page);

  // A message past the byte budget is refused, and names the limit. (maxlength
  // stops a human typing this, so set the value directly, as a paste would.)
  await page.locator('#message-input').evaluate((el, value) => {
    (el as HTMLInputElement).value = value;
    el.dispatchEvent(new Event('input', { bubbles: true }));
  }, 'x'.repeat(MAX_BYTES + 7));
  await page.locator('#encrypt-message').click();
  await expect(page.locator('#enc-status')).toHaveText(
    `Message is too long for N=${N}. Max ${MAX_BYTES} bytes.`,
  );
  await expect(page.locator('#message-input')).toHaveAttribute('aria-invalid', 'true');
  await expect(page.locator('#decrypt-message')).toBeDisabled();

  // Back inside the budget, the flow proceeds.
  await page.locator('#message-input').fill('short enough');
  await expect(page.locator('#message-input')).not.toHaveAttribute('aria-invalid', 'true');
  await encrypt(page);
  await expect(page.locator('#decrypt-message')).toBeEnabled();

  // Regenerating the key invalidates the ciphertext rather than decrypting it
  // against the wrong key.
  await generateKeypair(page);
  await expect(page.locator('#dec-status')).toHaveText(
    'Ciphertext invalidated after key regeneration. Re-encrypt to continue.',
  );
  await expect(page.locator('#decrypt-message')).toBeDisabled();
  await expect(page.locator('#tamper-ciphertext')).toBeDisabled();
  // And the equations re-lock to match.
  await expect(badges(page)).toHaveText([
    'h is on screen ✓',
    'Needs Encrypt',
    'Needs Decrypt',
    'Needs Decrypt',
  ]);
});

// ---------------------------------------------------------------------------
// Exhibit 3 Part A — Gauss-Lagrange reduction
// ---------------------------------------------------------------------------

interface LatticeState {
  step: number;
  total: number;
  description: string;
  b1: [number, number];
  b2: [number, number];
  norms: [number, number];
  shortest: number;
  det: number;
}

async function readLattice(page: Page): Promise<LatticeState> {
  const text = await flat(page.locator('#lll-readout'));
  const head = grab(text, /Step (\d+) \/ (\d+) (.+?) b₁ = /);
  const v1 = grab(text, /b₁ = \((-?[\d.]+), (-?[\d.]+)\) ‖b₁‖ = ([\d.]+)/);
  const v2 = grab(text, /b₂ = \((-?[\d.]+), (-?[\d.]+)\) ‖b₂‖ = ([\d.]+)/);
  const tail = grab(text, /shortest ‖·‖ = ([\d.]+) det = (\d+) \(invariant\)/);
  return {
    step: Number(head[1]),
    total: Number(head[2]),
    description: head[3]!,
    b1: [Number(v1[1]), Number(v1[2])],
    b2: [Number(v2[1]), Number(v2[2])],
    norms: [Number(v1[3]), Number(v2[3])],
    shortest: Number(tail[1]),
    det: Number(tail[2]),
  };
}

const norm2d = (v: [number, number]): number => Math.hypot(v[0], v[1]);
const det2d = (a: [number, number], b: [number, number]): number => Math.abs(a[0] * b[1] - a[1] * b[0]);

test('2D reduction: the determinant really is invariant and the basis really gets shorter', async ({
  page,
}) => {
  await open(page);

  const start = await readLattice(page);
  expect(start.step).toBe(0);
  expect(start.total).toBeGreaterThan(0);
  expect(start.det).toBeGreaterThan(0);
  await expect(page.locator('#lll-state')).toHaveText('Reduction in progress.');

  // The printed norms and determinant must be those of the printed vectors.
  expect(start.norms[0]).toBeCloseTo(norm2d(start.b1), 2);
  expect(start.norms[1]).toBeCloseTo(norm2d(start.b2), 2);
  expect(start.det).toBeCloseTo(det2d(start.b1, start.b2), 0);

  let previousShortest = start.shortest;
  let current = start;
  while (current.step < current.total) {
    await page.locator('#lll-step').click();
    const next = await readLattice(page);
    expect(next.step).toBe(current.step + 1);

    // The vectors and their norms agree with each other.
    expect(next.norms[0]).toBeCloseTo(norm2d(next.b1), 2);
    expect(next.norms[1]).toBeCloseTo(norm2d(next.b2), 2);
    // The page prints "det = … (invariant)"; every unimodular step must keep it,
    // and it must be the determinant of the basis on screen.
    expect(next.det, `determinant moved at step ${next.step}`).toBe(start.det);
    expect(next.det).toBeCloseTo(det2d(next.b1, next.b2), 0);
    // The printed "shortest" is the shorter of the two printed norms.
    expect(next.shortest).toBeCloseTo(Math.min(...next.norms), 3);
    // Reduction never lengthens the shortest vector.
    expect(next.shortest).toBeLessThanOrEqual(previousShortest + 1e-9);

    // Each step must be the operation it says it performed.
    if (next.description.startsWith('Swap so the shorter vector is b₁')) {
      expect(next.b1).toEqual(current.b2);
      expect(next.b2).toEqual(current.b1);
      expect(next.norms[0], 'after the swap b₁ must be the shorter vector').toBeLessThanOrEqual(
        next.norms[1] + 1e-9,
      );
    } else {
      const mu = Number(grab(next.description, /Size-reduce: b₂ ← b₂ − (-?\d+)·b₁/)[1]);
      expect(next.b1, 'a size-reduction leaves b₁ alone').toEqual(current.b1);
      expect(next.b2[0]).toBeCloseTo(current.b2[0] - mu * current.b1[0], 6);
      expect(next.b2[1]).toBeCloseTo(current.b2[1] - mu * current.b1[1], 6);
    }

    previousShortest = next.shortest;
    current = next;
  }

  // The terminating condition the last line claims: the projection rounds to 0.
  expect(current.description).toContain('projection μ = 0, basis reduced');
  const dot = current.b1[0] * current.b2[0] + current.b1[1] * current.b2[1];
  expect(Math.round(dot / norm2d(current.b1) ** 2)).toBe(0);

  // At the end the claim is made, and the step control retires.
  expect(current.shortest).toBeLessThan(start.shortest);
  await expect(page.locator('#lll-state')).toHaveText('Basis reduced: b₁ is a shortest lattice vector.');
  await expect(page.locator('#lll-step')).toBeDisabled();
  await expect(page.locator('#lll-step')).toHaveText('Reduced');

  // A new basis starts a new reduction from step 0.
  await page.locator('#lll-new').click();
  const fresh = await readLattice(page);
  expect(fresh.step).toBe(0);
  await expect(page.locator('#lll-step')).toBeEnabled();

  // Auto-reduce finishes the job.
  await page.locator('#lll-auto').click();
  await expect(page.locator('#lll-state')).toHaveText(
    'Basis reduced: b₁ is a shortest lattice vector.',
    { timeout: 30_000 },
  );
  const done = await readLattice(page);
  expect(done.step).toBe(done.total);
  expect(done.det).toBe(fresh.det);
});

// ---------------------------------------------------------------------------
// Exhibit 3 Part B — the real small-key lattice attack
// ---------------------------------------------------------------------------

const parseVector = (text: string): number[] => text.split(',').map((v) => Number(v.trim()));

/** rot_k(v)[i] = v[(i − k) mod n] — the page's cyclic-rotation convention. */
const rotate = (v: number[], k: number): number[] =>
  v.map((_, i) => v[(i - k + v.length * 2) % v.length]!);

test('lattice attack: the recovered short vector really is (p·g ‖ f) as the page claims', async ({
  page,
}) => {
  await open(page);

  const h = parseVector(grab(await flat(page.locator('#bridge-h')), /h = \[([^\]]*)\]/)[1]!);
  const params = grab(await flat(page.locator('#bridge-h')), /\(N=(\d+), q=(\d+), p=(\d+)\)/);
  const smallN = Number(params[1]);
  const smallQ = Number(params[2]);
  const p = Number(params[3]);
  expect(h).toHaveLength(smallN);
  // The public key is a real mod-q polynomial.
  for (const coefficient of h) {
    expect(coefficient).toBeGreaterThanOrEqual(0);
    expect(coefficient).toBeLessThan(smallQ);
  }
  // The secret stays hidden until the attack runs.
  await expect(page.locator('#bridge-secret')).toHaveText('f and g are hidden until you attack.');

  await page.locator('#bridge-attack').click();
  await expect(page.locator('#bridge-result')).toContainText(
    /LLL (recovered|did not recover) the key/,
  );

  const result = await flat(page.locator('#bridge-result'));
  const secret = await flat(page.locator('#bridge-secret'));
  const f = parseVector(grab(secret, /secret f = \[([^\]]*)\]/)[1]!);
  const pg = parseVector(grab(secret, /p·g = \[([^\]]*)\]/)[1]!);

  // f is ternary and p·g is p times a ternary polynomial — the "short" secret.
  expect(f).toHaveLength(smallN);
  expect(pg).toHaveLength(smallN);
  for (const coefficient of f) expect([-1, 0, 1]).toContain(coefficient);
  for (const coefficient of pg) expect([-p, 0, p]).toContain(coefficient);

  const shortest = grab(result, /(?:recovered|shortest) = \( \[([^\]]*)\] ‖ \[([^\]]*)\] \)/);
  const left = parseVector(shortest[1]!);
  const right = parseVector(shortest[2]!);
  expect(left).toHaveLength(smallN);
  expect(right).toHaveLength(smallN);

  if (result.includes('did not recover')) {
    // The honest negative path: no match is claimed, and the page says so.
    expect(result).toContain('no match was found');
    expect(result).not.toContain('is the private key');
    await expect(page.locator('#bridge-state')).toHaveText(
      'Attack complete: no matching private-key vector was found.',
    );
    return;
  }

  // The positive claim, verified independently against the printed secret.
  await expect(page.locator('#bridge-state')).toHaveText(
    'Attack complete: the short vector is the private key.',
  );
  const claim = grab(result, /= \( p·g ‖ f \), (an exact match|(negated and )?cyclically rotated by (\d+) — still a valid private key)/);
  const sign = claim[0].includes('negated') ? -1 : 1;
  const rotation = claim[1] === 'an exact match' ? 0 : Number(claim[3]);

  // `+ 0` normalizes the -0 that negating a zero coefficient produces, which
  // toEqual otherwise treats as distinct from 0.
  const expectedLeft = rotate(pg, rotation).map((v) => v * sign + 0);
  const expectedRight = rotate(f, rotation).map((v) => v * sign + 0);
  expect(left, `left half must be ${sign === -1 ? '−' : ''}rot_${rotation}(p·g)`).toEqual(expectedLeft);
  expect(right, `right half must be ${sign === -1 ? '−' : ''}rot_${rotation}(f)`).toEqual(expectedRight);
  if (claim[1] === 'an exact match') {
    expect(left).toEqual(pg);
    expect(right).toEqual(f);
  }

  // A new instance re-hides the secret and clears the verdict.
  await page.locator('#bridge-new').click();
  await expect(page.locator('#bridge-secret')).toHaveText('f and g are hidden until you attack.');
  await expect(page.locator('#bridge-result')).toContainText('Press Attack to run LLL');
  await expect(page.locator('#bridge-state')).toHaveText('A fresh small NTRU key is loaded.');
});
