export type Polynomial = Int32Array;

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

/** Positive modulo (JavaScript % is broken for negatives). */
export function modPos(a: number, m: number): number {
  const r = a % m;
  return r < 0 ? r + m : r;
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

function randomIntExclusive(maxExclusive: number): number {
  if (!Number.isInteger(maxExclusive) || maxExclusive <= 0) {
    throw new Error('maxExclusive must be a positive integer');
  }

  const maxUint = 0x1_0000_0000;
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
  if (dp < 0 || dm < 0 || dp + dm > N) {
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
