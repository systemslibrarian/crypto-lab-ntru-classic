import { modPos, multiply, reduceMod, type Polynomial } from './polynomial';

function trimPoly(poly: number[]): number[] {
  let end = poly.length;
  while (end > 0 && poly[end - 1] === 0) {
    end -= 1;
  }
  return poly.slice(0, end);
}

function degree(poly: number[]): number {
  for (let i = poly.length - 1; i >= 0; i -= 1) {
    if (poly[i] !== 0) {
      return i;
    }
  }
  return -1;
}

function modInverseInt(a: number, p: number): number | null {
  const aa = modPos(a, p);
  for (let x = 1; x < p; x += 1) {
    if (modPos(aa * x, p) === 1) {
      return x;
    }
  }
  return null;
}

function polyAddMod(a: number[], b: number[], p: number): number[] {
  const len = Math.max(a.length, b.length);
  const out = new Array<number>(len).fill(0);

  for (let i = 0; i < len; i += 1) {
    const av = i < a.length ? a[i] : 0;
    const bv = i < b.length ? b[i] : 0;
    out[i] = modPos(av + bv, p);
  }

  return trimPoly(out);
}

function polySubMod(a: number[], b: number[], p: number): number[] {
  const len = Math.max(a.length, b.length);
  const out = new Array<number>(len).fill(0);

  for (let i = 0; i < len; i += 1) {
    const av = i < a.length ? a[i] : 0;
    const bv = i < b.length ? b[i] : 0;
    out[i] = modPos(av - bv, p);
  }

  return trimPoly(out);
}

function polyMulMod(a: number[], b: number[], p: number): number[] {
  if (a.length === 0 || b.length === 0) {
    return [];
  }

  const out = new Array<number>(a.length + b.length - 1).fill(0);

  for (let i = 0; i < a.length; i += 1) {
    if (a[i] === 0) {
      continue;
    }
    for (let j = 0; j < b.length; j += 1) {
      if (b[j] === 0) {
        continue;
      }
      out[i + j] = modPos(out[i + j] + a[i] * b[j], p);
    }
  }

  return trimPoly(out);
}

function polyDivMod(
  numerator: number[],
  denominator: number[],
  p: number,
): { q: number[]; r: number[] } {
  const den = trimPoly(denominator);
  if (den.length === 0) {
    throw new Error('Polynomial division by zero');
  }

  const rem = trimPoly(numerator).slice();
  const qLen = Math.max(0, rem.length - den.length + 1);
  const quot = new Array<number>(qLen).fill(0);

  const denDeg = degree(den);
  const denLead = den[denDeg];
  const denLeadInv = modInverseInt(denLead, p);
  if (denLeadInv === null) {
    throw new Error('Denominator leading coefficient not invertible');
  }

  while (degree(rem) >= denDeg && degree(rem) >= 0) {
    const remDeg = degree(rem);
    const shift = remDeg - denDeg;
    const factor = modPos(rem[remDeg] * denLeadInv, p);
    quot[shift] = factor;

    for (let i = 0; i <= denDeg; i += 1) {
      rem[i + shift] = modPos(rem[i + shift] - factor * den[i], p);
    }

    while (rem.length > 0 && rem[rem.length - 1] === 0) {
      rem.pop();
    }
  }

  return {
    q: trimPoly(quot),
    r: trimPoly(rem),
  };
}

function reduceByXNMinus1(poly: number[], N: number, p: number): number[] {
  const out = new Array<number>(N).fill(0);
  for (let i = 0; i < poly.length; i += 1) {
    out[i % N] = modPos(out[i % N] + poly[i], p);
  }
  return out;
}

/**
 * Inverse of f in R = Z[X]/(X^N - 1) modulo prime p.
 * Extended Euclidean algorithm for polynomials.
 * Returns null if f not invertible.
 */
export function inverseModP(
  f: Polynomial,
  N: number,
  p: number,
): Polynomial | null {
  const fPoly = trimPoly(Array.from(reduceMod(f, p)));
  if (fPoly.length === 0) {
    return null;
  }

  const modulusPoly = new Array<number>(N + 1).fill(0);
  modulusPoly[0] = modPos(-1, p);
  modulusPoly[N] = 1;

  let r0 = trimPoly(modulusPoly);
  let r1 = fPoly;
  let s0: number[] = [1];
  let s1: number[] = [];
  let t0: number[] = [];
  let t1: number[] = [1];

  while (r1.length > 0) {
    const { q, r } = polyDivMod(r0, r1, p);

    const sNext = polySubMod(s0, polyMulMod(q, s1, p), p);
    const tNext = polySubMod(t0, polyMulMod(q, t1, p), p);

    r0 = r1;
    r1 = r;
    s0 = s1;
    s1 = sNext;
    t0 = t1;
    t1 = tNext;
  }

  if (r0.length === 0) {
    return null;
  }

  if (r0.length !== 1) {
    return null;
  }

  const c = r0[0];
  if (c === 0) {
    return null;
  }

  const cInv = modInverseInt(c, p);
  if (cInv === null) {
    return null;
  }

  const invRaw = t0.map((v) => modPos(v * cInv, p));
  const reduced = reduceByXNMinus1(invRaw, N, p);

  const out = new Int32Array(N);
  for (let i = 0; i < N; i += 1) {
    out[i] = reduced[i] ?? 0;
  }

  return out;
}

/**
 * Inverse of f mod q, where q = 2^k.
 * Algorithm (Silverman, 1998 Section 4.3.2):
 *   1. Compute F_2 = f^(-1) mod 2
 *   2. Hensel lift: for k = 1, 2, 4, 8, ... up to q:
 *        F_{2k} = F_k · (2 - f · F_k) mod 2k
 *   3. Return F_q
 */
export function inverseModQ(
  f: Polynomial,
  N: number,
  q: number,
): Polynomial | null {
  if ((q & (q - 1)) !== 0) {
    throw new Error('q must be a power of 2');
  }

  let F = inverseModP(f, N, 2);
  if (F === null) {
    return null;
  }

  let modulus = 2;
  while (modulus < q) {
    const nextModulus = modulus * 2;

    const fTimesF = multiply(f, F, nextModulus);
    const correction = new Int32Array(N);
    correction[0] = 2;

    for (let i = 0; i < N; i += 1) {
      correction[i] = modPos(correction[i] - fTimesF[i], nextModulus);
    }

    F = multiply(F, correction, nextModulus);
    modulus = nextModulus;
  }

  return isInverse(f, F, N, q) ? F : null;
}

/** Verify F is inverse of f mod m in R. */
export function isInverse(
  f: Polynomial,
  F: Polynomial,
  N: number,
  m: number,
): boolean {
  if (f.length !== N || F.length !== N) {
    return false;
  }

  const prod = multiply(f, F, m);
  if (prod[0] !== 1) {
    return false;
  }

  for (let i = 1; i < N; i += 1) {
    if (prod[i] !== 0) {
      return false;
    }
  }

  return true;
}
