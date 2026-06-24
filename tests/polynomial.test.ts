import { describe, expect, it } from 'vitest';
import {
  NTRU_PARAMS,
  add,
  centerReduce,
  modPos,
  multiply,
  randomTernary,
  reduceMod,
  subtract,
  zeroPoly,
} from '../src/polynomial';

describe('modPos', () => {
  it('returns a non-negative residue for negative inputs', () => {
    expect(modPos(-1, 3)).toBe(2);
    expect(modPos(-2048, 2048)).toBe(0);
    expect(modPos(5, 3)).toBe(2);
  });
});

describe('zeroPoly', () => {
  it('creates an all-zero Int32Array of the requested length', () => {
    const z = zeroPoly(5);
    expect(z.length).toBe(5);
    expect(Array.from(z)).toEqual([0, 0, 0, 0, 0]);
  });
});

describe('multiply (cyclic convolution in Z[X]/(X^N - 1))', () => {
  it('matches a hand-computed reference convolution', () => {
    const a = new Int32Array([1, 2, 0, 0]);
    const b = new Int32Array([0, 1, 1, 0]);
    expect(Array.from(multiply(a, b, 97))).toEqual([0, 1, 3, 2]);
  });

  it('wraps degree-N terms back to degree 0 (X^N = 1)', () => {
    // X^(N-1) * X = X^N = 1 in the ring.
    const N = 4;
    const a = new Int32Array([0, 0, 0, 1]); // X^3
    const b = new Int32Array([0, 1, 0, 0]); // X
    expect(Array.from(multiply(a, b, 7))).toEqual([1, 0, 0, 0]);
  });

  it('is commutative', () => {
    const a = new Int32Array([3, 1, 4, 1, 5]);
    const b = new Int32Array([2, 7, 1, 8, 2]);
    expect(Array.from(multiply(a, b, 13))).toEqual(Array.from(multiply(b, a, 13)));
  });

  it('treats the all-ones-at-zero polynomial as a multiplicative identity', () => {
    const id = new Int32Array([1, 0, 0, 0, 0]);
    const a = new Int32Array([5, 9, 2, 6, 5]);
    expect(Array.from(multiply(a, id, 11))).toEqual(Array.from(reduceMod(a, 11)));
  });

  it('throws on length mismatch', () => {
    expect(() => multiply(new Int32Array(3), new Int32Array(4), 5)).toThrow();
  });
});

describe('add / subtract', () => {
  it('adds coefficient-wise mod m', () => {
    const a = new Int32Array([1, 2, 3]);
    const b = new Int32Array([2, 2, 2]);
    expect(Array.from(add(a, b, 3))).toEqual([0, 1, 2]);
  });

  it('subtracts coefficient-wise with positive residues', () => {
    const a = new Int32Array([0, 0, 0]);
    const b = new Int32Array([1, 2, 3]);
    expect(Array.from(subtract(a, b, 5))).toEqual([4, 3, 2]);
  });
});

describe('centerReduce / reduceMod', () => {
  it('reduceMod puts coefficients in [0, m)', () => {
    const p = new Int32Array([-1, 2048, 4097]);
    expect(Array.from(reduceMod(p, 2048))).toEqual([2047, 0, 1]);
  });

  it('centerReduce puts coefficients in (-m/2, m/2]', () => {
    const p = new Int32Array([0, 1024, 1025, 2047]);
    // 1025 -> 1025-2048 = -1023 ; 2047 -> -1
    expect(Array.from(centerReduce(p, 2048))).toEqual([0, 1024, -1023, -1]);
  });
});

describe('randomTernary', () => {
  it('produces exactly dp +1s and dm -1s with the rest zero', () => {
    const N = 50;
    const dp = 10;
    const dm = 7;
    const poly = randomTernary(N, dp, dm);
    let plus = 0;
    let minus = 0;
    let zero = 0;
    for (const c of poly) {
      if (c === 1) plus += 1;
      else if (c === -1) minus += 1;
      else zero += 1;
    }
    expect(plus).toBe(dp);
    expect(minus).toBe(dm);
    expect(zero).toBe(N - dp - dm);
  });

  it('uses ees443ep1 counts without error', () => {
    const poly = randomTernary(NTRU_PARAMS.N, NTRU_PARAMS.df, NTRU_PARAMS.df - 1);
    expect(poly.length).toBe(NTRU_PARAMS.N);
  });

  it('rejects invalid counts', () => {
    expect(() => randomTernary(10, 6, 6)).toThrow();
    expect(() => randomTernary(10, -1, 0)).toThrow();
  });

  it('does not always return the same arrangement (randomized)', () => {
    const a = randomTernary(443, 143, 142);
    const b = randomTernary(443, 143, 142);
    expect(Array.from(a)).not.toEqual(Array.from(b));
  });
});
