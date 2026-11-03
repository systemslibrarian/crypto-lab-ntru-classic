import { describe, expect, it } from 'vitest';
import {
  NTRU_PARAMS,
  add,
  centerReduce,
  modPos,
  multiply,
  randomIntExclusive,
  rejectionLimit,
  type Uint32Source,
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

  it('uses the original-form L(df, df - 1) counts without error', () => {
    const poly = randomTernary(NTRU_PARAMS.N, NTRU_PARAMS.df, NTRU_PARAMS.df - 1);
    expect(poly.length).toBe(NTRU_PARAMS.N);
    expect(Array.from(poly).filter((c) => c === 1)).toHaveLength(NTRU_PARAMS.df);
    expect(Array.from(poly).filter((c) => c === -1)).toHaveLength(NTRU_PARAMS.df - 1);
  });

  it('rejects invalid counts', () => {
    expect(() => randomTernary(10, 6, 6)).toThrow();
    expect(() => randomTernary(10, -1, 0)).toThrow();
    expect(() => randomTernary(10.5, 1, 1)).toThrow();
    expect(() => randomTernary(10, 1.5, 1)).toThrow();
    expect(() => randomTernary(0, 0, 0)).toThrow();
    expect(() => randomTernary(2 ** 32 + 1, 1, 1)).toThrow();
  });

  it('does not always return the same arrangement (randomized)', () => {
    const a = randomTernary(443, 143, 142);
    const b = randomTernary(443, 143, 142);
    expect(Array.from(a)).not.toEqual(Array.from(b));
  });
});

describe('randomIntExclusive rejection bound', () => {
  /** Yields the given raw words in order, recording how many draws were taken. */
  function feed(words: number[], calls: number[] = []): Uint32Source {
    let i = 0;
    return (buf) => {
      calls.push(i);
      buf[0] = words[Math.min(i, words.length - 1)];
      i += 1;
    };
  }

  // maxExclusive = 10 on purpose: 2**32 % 10 is 6, so the discarded tail is six
  // values wide and a multi-redraw can be exercised. At 3 the tail is a single
  // value and bound + 1 wraps to 0, which is accepted.
  const maxExclusive = 10;
  // Derived WITHOUT calling the code under test: taking the bound from
  // rejectionLimit would move this expectation along with any mutation of it.
  const bound = 0x1_0000_0000 - (0x1_0000_0000 % maxExclusive);

  it('is the largest multiple of the bound inside 32 bits', () => {
    expect(rejectionLimit(maxExclusive)).toBe(bound);
    expect(bound % maxExclusive).toBe(0);
    expect(0x1_0000_0000 - bound).toBe(0x1_0000_0000 % maxExclusive);
  });

  it('uses the largest accepted raw value, in one draw', () => {
    const calls: number[] = [];
    expect(randomIntExclusive(maxExclusive, feed([bound - 1], calls))).toBe(
      (bound - 1) % maxExclusive,
    );
    expect(calls).toHaveLength(1);
  });

  it('redraws on the smallest rejected raw value, taking two draws', () => {
    const calls: number[] = [];
    expect(randomIntExclusive(maxExclusive, feed([bound, 7], calls))).toBe(7 % maxExclusive);
    expect(calls).toHaveLength(2);
  });

  it('keeps redrawing while the source stays in the tail', () => {
    const calls: number[] = [];
    expect(
      randomIntExclusive(maxExclusive, feed([bound, bound + 3, bound + 5, 5], calls)),
    ).toBe(5 % maxExclusive);
    expect(calls).toHaveLength(4);
  });

  it('reaches every value in range and none outside it', () => {
    const seen = new Set<number>();
    for (let v = 0; v < 64; v += 1) seen.add(randomIntExclusive(maxExclusive, feed([v])));
    expect([...seen].sort((a, b) => a - b)).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
  });
});

describe('randomIntExclusive', () => {
  it('stays inside the requested range and rejects impossible bounds', () => {
    for (let i = 0; i < 100; i += 1) {
      const value = randomIntExclusive(7);
      expect(value).toBeGreaterThanOrEqual(0);
      expect(value).toBeLessThan(7);
    }
    expect(() => randomIntExclusive(0)).toThrow();
    expect(() => randomIntExclusive(2 ** 32 + 1)).toThrow();
  });
});
