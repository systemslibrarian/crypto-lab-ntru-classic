import { describe, expect, it } from 'vitest';
import {
  type Vec2,
  dot,
  gaussReduce,
  norm,
  norm2,
  randomBadBasis,
} from '../src/lattice';

function det(b1: Vec2, b2: Vec2): number {
  return b1.x * b2.y - b1.y * b2.x;
}

describe('gaussReduce', () => {
  it('preserves the lattice determinant (operations are unimodular)', () => {
    const start1 = { x: 12, y: 2 };
    const start2 = { x: 13, y: 4 };
    const before = Math.abs(det(start1, start2));
    const trace = gaussReduce(start1, start2);
    const last = trace[trace.length - 1];
    expect(Math.abs(det(last.b1, last.b2))).toBeCloseTo(before, 9);
  });

  it('produces a reduced basis: ‖b1‖ ≤ ‖b2‖ and |⟨b1,b2⟩| ≤ ‖b1‖²/2', () => {
    const trace = gaussReduce({ x: 66, y: 68 }, { x: 39, y: 41 });
    const { b1, b2 } = trace[trace.length - 1];
    expect(norm2(b1)).toBeLessThanOrEqual(norm2(b2) + 1e-9);
    expect(Math.abs(dot(b1, b2))).toBeLessThanOrEqual(norm2(b1) / 2 + 1e-9);
  });

  it('the final b1 is no longer than either starting vector', () => {
    const start1 = { x: 20, y: 3 };
    const start2 = { x: 23, y: 5 };
    const trace = gaussReduce(start1, start2);
    const final = trace[trace.length - 1];
    expect(norm(final.b1)).toBeLessThanOrEqual(Math.min(norm(start1), norm(start2)) + 1e-9);
  });

  it('marks exactly the last step as done and starts with the initial state', () => {
    const trace = gaussReduce({ x: 7, y: 1 }, { x: 8, y: 2 });
    expect(trace[0].description).toMatch(/initial/i);
    expect(trace[trace.length - 1].done).toBe(true);
    expect(trace.slice(0, -1).every((s) => !s.done)).toBe(true);
  });

  it('handles an already-reduced basis in zero reduction steps', () => {
    // Orthonormal-ish basis is already reduced; only the initial state remains.
    const trace = gaussReduce({ x: 1, y: 0 }, { x: 0, y: 1 });
    expect(trace).toHaveLength(1);
    expect(trace[0].done).toBe(true);
  });
});

describe('randomBadBasis + gaussReduce (fuzz)', () => {
  it('always reduces to a valid reduced basis preserving the determinant', () => {
    for (let i = 0; i < 200; i += 1) {
      const { b1, b2 } = randomBadBasis();
      const d0 = Math.abs(det(b1, b2));
      expect(d0).toBeGreaterThan(0);
      const trace = gaussReduce(b1, b2);
      const final = trace[trace.length - 1];
      expect(norm2(final.b1)).toBeLessThanOrEqual(norm2(final.b2) + 1e-9);
      expect(Math.abs(det(final.b1, final.b2))).toBeCloseTo(d0, 6);
      expect(final.done).toBe(true);
    }
  });
});
