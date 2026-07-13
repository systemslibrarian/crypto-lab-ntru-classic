import { describe, expect, it } from 'vitest';
import { multiply, modPos } from '../src/polynomial';
import {
  buildLatticeBridge,
  centerMod,
  lllReduce,
  TOY_LATTICE_PARAMS,
} from '../src/ntru-lattice';

function rotate(a: number[], shift: number): number[] {
  const n = a.length;
  const out = new Array<number>(n).fill(0);
  for (let i = 0; i < n; i += 1) {
    out[(i + shift) % n] = a[i];
  }
  return out;
}

describe('ntru lattice bridge (honest small instance)', () => {
  it('LLL does not shorten an already-reduced identity basis', () => {
    const reduced = lllReduce([
      [1, 0],
      [0, 1],
    ]);
    // Rows stay unit length (possibly reordered/negated).
    for (const row of reduced) {
      expect(row[0] * row[0] + row[1] * row[1]).toBe(1);
    }
  });

  it('LLL finds a short vector in a sheared 2D lattice', () => {
    // (1,0),(0,1) sheared: (1,0),(20,1). Short vector (1,0) must survive.
    const reduced = lllReduce([
      [1, 0],
      [20, 1],
    ]);
    const norms = reduced.map((r) => r[0] * r[0] + r[1] * r[1]).sort((a, b) => a - b);
    expect(norms[0]).toBe(1);
  });

  it('builds a real public key satisfying f·h ≡ p·g (mod q)', () => {
    for (let trial = 0; trial < 20; trial += 1) {
      const bridge = buildLatticeBridge();
      const { N, p, q, f, g, h } = bridge;
      expect(N).toBe(TOY_LATTICE_PARAMS.N);
      // h must be a genuine polynomial mod q, not all-zero.
      expect(h.some((v) => v !== 0)).toBe(true);
      // f and g are ternary.
      expect(f.every((v) => v === -1 || v === 0 || v === 1)).toBe(true);
      expect(g.every((v) => v === -1 || v === 0 || v === 1)).toBe(true);
      const fh = multiply(Int32Array.from(f), Int32Array.from(h), q);
      const pg = g.map((x) => x * p);
      for (let i = 0; i < N; i += 1) {
        expect(centerMod(fh[i], q)).toBe(pg[i]);
      }
    }
  });

  it('LLL recovers the private key as the short lattice vector', () => {
    for (let trial = 0; trial < 25; trial += 1) {
      const bridge = buildLatticeBridge();
      const { N, f, g, p, reduced, shortestIndex, recovery } = bridge;
      const row = reduced[shortestIndex];
      expect(row).toBeDefined();
      const first = row.slice(0, N);
      const second = row.slice(N);
      // `+ 0` normalizes any -0 produced by `x * -1` so toEqual compares cleanly.
      const pg = g.map((x) => x * p);
      const rf = rotate(f, recovery.rotation).map((x) => x * recovery.sign + 0);
      const rpg = rotate(pg, recovery.rotation).map((x) => x * recovery.sign + 0);
      // Recovered row IS ±(a rotation of) the key (p·g ‖ f) — not asserted, verified.
      expect(second).toEqual(rf);
      expect(first).toEqual(rpg);
    }
  });

  it('the recovered key vector is genuinely short (shortest-first ordering holds)', () => {
    const bridge = buildLatticeBridge();
    const norm2 = (r: number[]) => r.reduce((s, v) => s + v * v, 0);
    const norms = bridge.reduced.map(norm2);
    for (let i = 1; i < norms.length; i += 1) {
      expect(norms[i]).toBeGreaterThanOrEqual(norms[i - 1]);
    }
    // The key-bearing row is among the shortest handful.
    expect(bridge.shortestIndex).toBeLessThan(bridge.N);
  });
});

describe('centerMod', () => {
  it('maps into (−m/2, m/2]', () => {
    expect(centerMod(30, 32)).toBe(-2);
    expect(centerMod(2, 32)).toBe(2);
    expect(centerMod(16, 32)).toBe(16);
    expect(modPos(-2, 32)).toBe(30);
  });
});
