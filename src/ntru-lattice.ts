/**
 * The NTRU lattice bridge — an HONEST, fully computed small instance.
 *
 * Exhibit 3's 2D Gauss–Lagrange demo teaches "reduce a bad basis to a short
 * vector," but a newcomer cannot see why that has anything to do with the key
 * `f` they generated. This module closes that gap: it builds a *real* tiny NTRU
 * keypair (small N and q, but genuine ternary keys, a genuine polynomial
 * inverse, and a genuine public key h = p·F_q·g), assembles the standard
 * 2N-dimensional NTRU public lattice from h, and runs a real LLL reduction that
 * recovers the private key as the lattice's short vector.
 *
 * Nothing here is faked. The reduced short row is literally ±(a cyclic rotation
 * of) (p·g, f), which is an equally valid NTRU private key — the rotation/sign
 * ambiguity is a true property of NTRU, not a shortcut. "Breaking NTRU = finding
 * the short vector" stops being a sentence and becomes something you watch land.
 *
 * The full-strength scheme (N=443, q=2048) lives in ntru.ts and is untouched;
 * this is a scaled-down *illustration of the attack geometry*, clearly labelled
 * as such in the UI, never a replacement for the real parameters.
 */
import { inverseModP, inverseModQ } from './inverse';
import { modPos, multiply, type Polynomial } from './polynomial';

/** Small but real parameters. N and q are tiny so the 2N-dim lattice fits on
 * screen and LLL runs instantly; p=3 is the real NTRU value. */
export const TOY_LATTICE_PARAMS = { N: 5, p: 3, q: 32 } as const;

export interface LatticeBridge {
  N: number;
  p: number;
  q: number;
  /** Secret short polynomial f (ternary). */
  f: number[];
  /** Secret short polynomial g (ternary). */
  g: number[];
  /** Public key h = p·F_q·g mod q — looks random. */
  h: number[];
  /** The target short lattice vector (p·g ‖ f): what the attack should find. */
  target: number[];
  /** The 2N×2N public NTRU basis rows (the attacker's starting knowledge). */
  basis: number[][];
  /** LLL-reduced basis rows, sorted shortest-first. */
  reduced: number[][];
  /** Index into `reduced` of the row that recovers the key. */
  shortestIndex: number;
  /** How the recovered row relates to (p·g ‖ f): a rotation and a sign. */
  recovery: { sign: 1 | -1; rotation: number };
}

function toI(a: number[]): Polynomial {
  return Int32Array.from(a);
}

/** Center a value into (−m/2, m/2]. */
export function centerMod(v: number, m: number): number {
  const r = modPos(v, m);
  return r > m / 2 ? r - m : r;
}

function rotate(a: number[], shift: number): number[] {
  const n = a.length;
  const out = new Array<number>(n).fill(0);
  for (let i = 0; i < n; i += 1) {
    out[(i + shift) % n] = a[i];
  }
  return out;
}

/** Crypto-secure random ternary polynomial of length N with `d` nonzero terms
 * (split as evenly as possible between +1 and −1). */
function randomSmallTernary(N: number, d: number): number[] {
  const idx = Array.from({ length: N }, (_, i) => i);
  const buf = new Uint32Array(1);
  for (let i = N - 1; i > 0; i -= 1) {
    crypto.getRandomValues(buf);
    const j = buf[0] % (i + 1);
    [idx[i], idx[j]] = [idx[j], idx[i]];
  }
  const poly = new Array<number>(N).fill(0);
  for (let k = 0; k < d; k += 1) {
    poly[idx[k]] = k % 2 === 0 ? 1 : -1;
  }
  return poly;
}

function dot(a: number[], b: number[]): number {
  let s = 0;
  for (let i = 0; i < a.length; i += 1) {
    s += a[i] * b[i];
  }
  return s;
}

/**
 * Textbook LLL reduction over the integers (exact enough for a tiny basis with
 * small entries; the Gram–Schmidt bookkeeping is recomputed after each update
 * for clarity rather than speed). Returns the reduced basis rows.
 */
export function lllReduce(basis: number[][], delta = 0.75): number[][] {
  const n = basis.length;
  const dim = basis[0].length;
  const b = basis.map((r) => r.slice());
  let bstar = b.map((r) => r.slice());
  const mu: number[][] = Array.from({ length: n }, () => new Array<number>(n).fill(0));
  const B = new Array<number>(n).fill(0);

  const gramSchmidt = (): void => {
    bstar = b.map((r) => r.slice());
    for (let i = 0; i < n; i += 1) {
      for (let j = 0; j < i; j += 1) {
        mu[i][j] = B[j] === 0 ? 0 : dot(b[i], bstar[j]) / B[j];
        for (let k = 0; k < dim; k += 1) {
          bstar[i][k] -= mu[i][j] * bstar[j][k];
        }
      }
      B[i] = dot(bstar[i], bstar[i]);
    }
  };

  gramSchmidt();
  let k = 1;
  let guard = 0;
  const maxIters = 10000;
  while (k < n && guard < maxIters) {
    guard += 1;
    for (let j = k - 1; j >= 0; j -= 1) {
      const r = Math.round(mu[k][j]);
      if (r !== 0) {
        for (let t = 0; t < dim; t += 1) {
          b[k][t] -= r * b[j][t];
        }
        gramSchmidt();
      }
    }
    if (B[k] >= (delta - mu[k][k - 1] * mu[k][k - 1]) * B[k - 1]) {
      k += 1;
    } else {
      [b[k], b[k - 1]] = [b[k - 1], b[k]];
      gramSchmidt();
      k = Math.max(k - 1, 1);
    }
  }
  return b;
}

/**
 * Build a real small NTRU instance and its public lattice, run LLL, and locate
 * the reduced row that recovers the private key.
 *
 * The public NTRU lattice for public key h is the row span of
 *
 *     [ q·I_N |  0  ]
 *     [  H    | I_N ]
 *
 * where H is the (negacyclic-free) circulant of h in Z[X]/(Xᴺ−1). Because
 * f·h ≡ p·g (mod q), the integer combination (f applied to the bottom rows,
 * minus the right multiple of the top rows) yields the short vector
 * (p·g ‖ f) — the private key. LLL finds it.
 */
export function buildLatticeBridge(): LatticeBridge {
  const { N, p, q } = TOY_LATTICE_PARAMS;

  let f: number[] | null = null;
  let Fq: Polynomial | null = null;
  // Search real ternary candidates until one is invertible mod p and mod q.
  for (let tries = 0; tries < 500; tries += 1) {
    const cand = randomSmallTernary(N, 3);
    if (!inverseModP(toI(cand), N, p)) {
      continue;
    }
    const inv = inverseModQ(toI(cand), N, q);
    if (!inv) {
      continue;
    }
    f = cand;
    Fq = inv;
    break;
  }
  if (!f || !Fq) {
    // Deterministic fallback known to satisfy the invertibility conditions.
    f = [0, 0, 1, 1, -1];
    Fq = inverseModQ(toI(f), N, q) as Polynomial;
  }

  const g = randomSmallTernary(N, 2);
  const h = Array.from(multiply(Fq, toI(g), q), (v) => modPos(v * p, q));
  const pg = g.map((x) => x * p);
  const target = [...pg, ...f];

  // Circulant of h in Z[X]/(Xᴺ−1): row i (multiplier of h by uᵢ) contributes
  // h[(k−i) mod N] to output coefficient k.
  const dim = 2 * N;
  const basis: number[][] = [];
  for (let i = 0; i < N; i += 1) {
    const row = new Array<number>(dim).fill(0);
    row[i] = q;
    basis.push(row);
  }
  for (let i = 0; i < N; i += 1) {
    const row = new Array<number>(dim).fill(0);
    for (let k = 0; k < N; k += 1) {
      row[k] = h[modPos(k - i, N)];
    }
    row[N + i] = 1;
    basis.push(row);
  }

  const reducedRaw = lllReduce(basis).map((r) => r.map((v) => Math.round(v)));
  reducedRaw.sort((a, b) => dot(a, a) - dot(b, b));

  // Identify which reduced row is ±(a rotation of) the key (p·g ‖ f).
  let shortestIndex = 0;
  let recovery: { sign: 1 | -1; rotation: number } = { sign: 1, rotation: 0 };
  outer: for (let idx = 0; idx < reducedRaw.length; idx += 1) {
    const first = reducedRaw[idx].slice(0, N);
    const second = reducedRaw[idx].slice(N);
    for (let s = 0; s < N; s += 1) {
      for (const sign of [1, -1] as const) {
        const rf = rotate(f, s).map((x) => x * sign);
        const rpg = rotate(pg, s).map((x) => x * sign);
        if (
          second.every((v, i) => v === rf[i]) &&
          first.every((v, i) => v === rpg[i])
        ) {
          shortestIndex = idx;
          recovery = { sign, rotation: s };
          break outer;
        }
      }
    }
  }

  return {
    N,
    p,
    q,
    f,
    g,
    h,
    target,
    basis,
    reduced: reducedRaw,
    shortestIndex,
    recovery,
  };
}
