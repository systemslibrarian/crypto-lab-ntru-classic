/**
 * Gauss–Lagrange reduction of a 2-dimensional lattice basis.
 *
 * This is the exact two-dimensional analogue of LLL: it provably returns a
 * basis whose first vector is a shortest nonzero lattice vector. NTRU keys live
 * in a 2N-dimensional lattice where the same idea (find the short vector) is the
 * attack — but in 2D we can compute and animate every step honestly.
 *
 * Algorithm (each loop iteration is one or two atomic, visible operations):
 *   repeat:
 *     if ‖b1‖ > ‖b2‖: swap b1, b2          (keep the shorter vector first)
 *     μ = round(⟨b1, b2⟩ / ⟨b1, b1⟩)        (Gram–Schmidt projection, rounded)
 *     if μ = 0: stop                         (b2 can no longer be shortened)
 *     b2 ← b2 − μ·b1                          (size reduction)
 */

export interface Vec2 {
  x: number;
  y: number;
}

export interface ReductionStep {
  b1: Vec2;
  b2: Vec2;
  /** Human-readable description of the operation that produced this state. */
  description: string;
  /** Integer multiple used in a size-reduction step, otherwise null. */
  mu: number | null;
  /** True if this step swapped b1 and b2. */
  swapped: boolean;
  /** True once the basis is reduced (terminal step). */
  done: boolean;
  /** Euclidean norms (‖b1‖, ‖b2‖) at this state. */
  norms: [number, number];
  /** The shorter of the two basis vectors at this state. */
  shortest: Vec2;
}

export function dot(a: Vec2, b: Vec2): number {
  return a.x * b.x + a.y * b.y;
}

export function norm2(a: Vec2): number {
  return dot(a, a);
}

export function norm(a: Vec2): number {
  return Math.sqrt(norm2(a));
}

function snapshot(
  b1: Vec2,
  b2: Vec2,
  description: string,
  mu: number | null,
  swapped: boolean,
  done: boolean,
): ReductionStep {
  const shortest = norm2(b1) <= norm2(b2) ? b1 : b2;
  return {
    b1: { ...b1 },
    b2: { ...b2 },
    description,
    mu,
    swapped,
    done,
    norms: [norm(b1), norm(b2)],
    shortest: { ...shortest },
  };
}

/**
 * Run Gauss–Lagrange reduction, returning the full trace of intermediate
 * states (including the initial state) so the UI can step through it.
 */
export function gaussReduce(start1: Vec2, start2: Vec2, maxSteps = 64): ReductionStep[] {
  let b1: Vec2 = { ...start1 };
  let b2: Vec2 = { ...start2 };

  const trace: ReductionStep[] = [
    snapshot(b1, b2, 'Initial basis: long, nearly parallel vectors', null, false, false),
  ];

  for (let i = 0; i < maxSteps; i += 1) {
    if (norm2(b1) > norm2(b2)) {
      const t = b1;
      b1 = b2;
      b2 = t;
      trace.push(snapshot(b1, b2, 'Swap so the shorter vector is b₁', null, true, false));
    }

    const denom = norm2(b1);
    if (denom === 0) {
      break;
    }

    const mu = Math.round(dot(b1, b2) / denom);
    if (mu === 0) {
      const last = trace[trace.length - 1];
      last.done = true;
      last.description = `${last.description} → projection μ = 0, basis reduced; b₁ is a shortest vector`;
      return trace;
    }

    b2 = { x: b2.x - mu * b1.x, y: b2.y - mu * b1.y };
    trace.push(snapshot(b1, b2, `Size-reduce: b₂ ← b₂ − ${mu}·b₁`, mu, false, false));
  }

  trace[trace.length - 1].done = true;
  return trace;
}

function randIntInclusive(min: number, max: number): number {
  const span = max - min + 1;
  const maxUint = 0x1_0000_0000;
  const limit = maxUint - (maxUint % span);
  const buf = new Uint32Array(1);
  while (true) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) {
      return min + (buf[0] % span);
    }
  }
}

/**
 * Generate a deliberately "bad" basis: start from a short, near-orthogonal
 * basis and apply random unimodular shears. Shears preserve the lattice (and
 * its determinant) but inflate the basis vectors into long, near-parallel ones,
 * so reduction reliably recovers a genuinely short vector.
 */
export function randomBadBasis(): { b1: Vec2; b2: Vec2 } {
  while (true) {
    let b1: Vec2 = { x: randIntInclusive(1, 3), y: randIntInclusive(-2, 2) };
    let b2: Vec2 = { x: randIntInclusive(-2, 2), y: randIntInclusive(1, 3) };

    // Require an independent (nonzero-determinant) starting basis.
    if (b1.x * b2.y - b1.y * b2.x === 0) {
      continue;
    }

    const shears = randIntInclusive(2, 3);
    for (let i = 0; i < shears; i += 1) {
      const k = randIntInclusive(2, 4) * (randIntInclusive(0, 1) === 0 ? 1 : -1);
      if (i % 2 === 0) {
        b2 = { x: b2.x + k * b1.x, y: b2.y + k * b1.y };
      } else {
        b1 = { x: b1.x + k * b2.x, y: b1.y + k * b2.y };
      }
    }

    // Reject pathological cases that are too small to look "bad" or so large
    // they overflow the canvas; aim for an illustrative middle range.
    const longest = Math.max(norm(b1), norm(b2));
    if (longest >= 5 && longest <= 40) {
      return { b1, b2 };
    }
  }
}
