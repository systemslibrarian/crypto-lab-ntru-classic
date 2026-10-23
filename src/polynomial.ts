export type Polynomial = Int32Array;

/**
 * Fixed-weight educational profile used throughout the demo.
 *
 * The original HPS paper defines L_f = L(df, df - 1), L_g = L(dg, dg), and
 * L_phi = L(d, d). This demo follows those coefficient shapes and chooses
 * df = dg = dr = 143. Its N = 443, p = 3, q = 2048 scale and the number 143
 * echo Table 1's NTRU-443 row in the first-round NTRUEncrypt submission, but
 * this combination is an educational hybrid rather than a published profile.
 *
 * It is not an implementation of the submitted ntru-pke-443 scheme. That
 * construction used h = g/(p f + 1), padding, message masking, deterministic
 * coins, and decrypt-and-verify rejection that are absent here. Its security
 * estimates therefore do not transfer to this teaching profile. The N = 443
 * row in ePrint 2015/708 is also product-form, not this flat distribution.
 */
export const NTRU_PARAMS = {
  N: 443,
  p: 3,
  q: 2048,
  df: 143,
  dg: 143,
  dr: 143,
} as const;

/** Create zero polynomial of length n. */
export function zeroPoly(n: number): Polynomial {
  return new Int32Array(n);
}

/** Positive modulo (JavaScript % is broken for negatives, and yields -0). */
export function modPos(a: number, m: number): number {
  const r = a % m;
  if (r < 0) {
    return r + m;
  }
  // Normalize -0 (e.g. -2048 % 2048) to +0 so it never reaches coefficients.
  return r === 0 ? 0 : r;
}

/** Center-reduce: coefficients into [-m/2, m/2]. */
export function centerReduce(p: Polynomial, m: number): Polynomial {
  const out = new Int32Array(p.length);
  const half = m / 2;

  for (let i = 0; i < p.length; i += 1) {
    const v = modPos(p[i], m);
    out[i] = v > half ? v - m : v;
  }

  return out;
}

/** Reduce coefficients mod m, result in [0, m). */
export function reduceMod(p: Polynomial, m: number): Polynomial {
  const out = new Int32Array(p.length);
  for (let i = 0; i < p.length; i += 1) {
    out[i] = modPos(p[i], m);
  }
  return out;
}

/**
 * Convolution in R = Z[X]/(X^N - 1), reduced mod m.
 * (a * b)[k] = Σᵢ a[i] · b[(k-i) mod N]
 */
export function multiply(a: Polynomial, b: Polynomial, m: number): Polynomial {
  if (a.length !== b.length) {
    throw new Error('Polynomial length mismatch');
  }

  const n = a.length;
  const accum = new Float64Array(n);

  for (let i = 0; i < n; i += 1) {
    const ai = a[i];
    if (ai === 0) {
      continue;
    }

    for (let j = 0; j < n; j += 1) {
      const bj = b[j];
      if (bj === 0) {
        continue;
      }

      const k = i + j;
      const wrapped = k >= n ? k - n : k;
      accum[wrapped] += ai * bj;
    }
  }

  const out = new Int32Array(n);
  for (let i = 0; i < n; i += 1) {
    out[i] = modPos(accum[i], m);
  }

  return out;
}

export function add(a: Polynomial, b: Polynomial, m: number): Polynomial {
  if (a.length !== b.length) {
    throw new Error('Polynomial length mismatch');
  }

  const out = new Int32Array(a.length);
  for (let i = 0; i < a.length; i += 1) {
    out[i] = modPos(a[i] + b[i], m);
  }
  return out;
}

export function subtract(a: Polynomial, b: Polynomial, m: number): Polynomial {
  if (a.length !== b.length) {
    throw new Error('Polynomial length mismatch');
  }

  const out = new Int32Array(a.length);
  for (let i = 0; i < a.length; i += 1) {
    out[i] = modPos(a[i] - b[i], m);
  }
  return out;
}

export function randomIntExclusive(maxExclusive: number): number {
  const maxUint = 0x1_0000_0000;
  if (
    !Number.isSafeInteger(maxExclusive) ||
    maxExclusive <= 0 ||
    maxExclusive > maxUint
  ) {
    throw new Error('maxExclusive must be an integer in [1, 2^32]');
  }

  const limit = maxUint - (maxUint % maxExclusive);
  const buf = new Uint32Array(1);

  while (true) {
    crypto.getRandomValues(buf);
    const value = buf[0];
    if (value < limit) {
      return value % maxExclusive;
    }
  }
}

/** Random ternary poly with exactly dp +1, dm -1, rest 0. */
export function randomTernary(N: number, dp: number, dm: number): Polynomial {
  if (
    !Number.isSafeInteger(N) ||
    !Number.isSafeInteger(dp) ||
    !Number.isSafeInteger(dm) ||
    N <= 0 ||
    N > 0x1_0000_0000 ||
    dp < 0 ||
    dm < 0 ||
    dp + dm > N
  ) {
    throw new Error('Invalid ternary counts');
  }

  const poly = new Int32Array(N);
  const indices = new Int32Array(N);

  for (let i = 0; i < N; i += 1) {
    indices[i] = i;
  }

  // Fisher-Yates shuffle with crypto-secure randomness.
  for (let i = N - 1; i > 0; i -= 1) {
    const j = randomIntExclusive(i + 1);
    const t = indices[i];
    indices[i] = indices[j];
    indices[j] = t;
  }

  for (let i = 0; i < dp; i += 1) {
    poly[indices[i]] = 1;
  }

  for (let i = dp; i < dp + dm; i += 1) {
    poly[indices[i]] = -1;
  }

  return poly;
}
