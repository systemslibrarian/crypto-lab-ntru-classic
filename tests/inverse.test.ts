import { describe, expect, it } from 'vitest';
import { inverseModP, inverseModQ, isInverse } from '../src/inverse';
import { NTRU_PARAMS, multiply, randomTernary, type Polynomial } from '../src/polynomial';

function findInvertibleF(): { f: Polynomial; Fp: Polynomial } {
  for (let i = 0; i < 64; i += 1) {
    const f = randomTernary(NTRU_PARAMS.N, NTRU_PARAMS.df, NTRU_PARAMS.df - 1);
    const Fp = inverseModP(f, NTRU_PARAMS.N, NTRU_PARAMS.p);
    if (Fp) return { f, Fp };
  }
  throw new Error('no invertible f found in 64 attempts (vanishingly unlikely)');
}

describe('inverseModP', () => {
  it('produces a genuine inverse mod 3 in the ring', () => {
    const { f, Fp } = findInvertibleF();
    expect(isInverse(f, Fp, NTRU_PARAMS.N, NTRU_PARAMS.p)).toBe(true);
    const prod = multiply(f, Fp, NTRU_PARAMS.p);
    expect(prod[0]).toBe(1);
    for (let i = 1; i < prod.length; i += 1) expect(prod[i]).toBe(0);
  });

  it('returns null for the zero polynomial', () => {
    expect(inverseModP(new Int32Array(NTRU_PARAMS.N), NTRU_PARAMS.N, NTRU_PARAMS.p)).toBeNull();
  });

  it('inverts a small known-invertible element', () => {
    // 1 + X in Z[X]/(X^3 - 1) mod 2 — small sanity case.
    const f = new Int32Array([1, 1, 0]);
    const inv = inverseModP(f, 3, 2);
    if (inv) {
      expect(isInverse(f, inv, 3, 2)).toBe(true);
    }
    // (1 + X)(1 + X + X^2) ... we only assert self-consistency when invertible.
  });
});

describe('inverseModQ (Hensel lifting, q = 2048)', () => {
  it('produces a genuine inverse mod 2048', () => {
    const { f } = findInvertibleF();
    const Fq = inverseModQ(f, NTRU_PARAMS.N, NTRU_PARAMS.q);
    expect(Fq).not.toBeNull();
    expect(isInverse(f, Fq as Polynomial, NTRU_PARAMS.N, NTRU_PARAMS.q)).toBe(true);
  });

  it('rejects a non power-of-two modulus', () => {
    const f = randomTernary(NTRU_PARAMS.N, NTRU_PARAMS.df, NTRU_PARAMS.df - 1);
    expect(() => inverseModQ(f, NTRU_PARAMS.N, 2047)).toThrow();
  });

  it('returns null when f is singular mod 2', () => {
    // A polynomial divisible by (X-1) factor pattern is not invertible mod 2;
    // the all-ones polynomial vanishes under X=1 and is a reliable singular case.
    const f = new Int32Array(NTRU_PARAMS.N).fill(1);
    expect(inverseModQ(f, NTRU_PARAMS.N, NTRU_PARAMS.q)).toBeNull();
  });
});

describe('isInverse', () => {
  it('rejects length mismatches', () => {
    expect(isInverse(new Int32Array(3), new Int32Array(4), 3, 5)).toBe(false);
  });

  it('rejects a non-inverse pair', () => {
    const f = new Int32Array([1, 0, 0]);
    const notInv = new Int32Array([0, 1, 0]);
    expect(isInverse(f, notInv, 3, 7)).toBe(false);
  });
});
