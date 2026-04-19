import { inverseModP, inverseModQ } from './inverse';
import {
  NTRU_PARAMS,
  add,
  centerReduce,
  modPos,
  multiply,
  randomTernary,
  reduceMod,
  type Polynomial,
} from './polynomial';

export interface NTRUKeyPair {
  privateKey: { f: Polynomial; F_p: Polynomial };
  publicKey: Polynomial;
  generationAttempts: number;
}

function toBalancedMod3(poly: Polynomial): Polynomial {
  const out = new Int32Array(poly.length);
  for (let i = 0; i < poly.length; i += 1) {
    const v = modPos(poly[i], 3);
    out[i] = v === 2 ? -1 : v;
  }
  return out;
}

function scalePoly(poly: Polynomial, scalar: number, m: number): Polynomial {
  const out = new Int32Array(poly.length);
  for (let i = 0; i < poly.length; i += 1) {
    out[i] = modPos(poly[i] * scalar, m);
  }
  return out;
}

/**
 * Generate keypair. Retries if f not invertible.
 * onAttempt callback exposes retry loop for UI visibility.
 */
export function generateKeyPair(
  onAttempt?: (attempt: number, reason: string) => void,
): NTRUKeyPair {
  let attempt = 0;

  while (true) {
    attempt += 1;
    onAttempt?.(attempt, 'Generating random f');

    const f = randomTernary(NTRU_PARAMS.N, NTRU_PARAMS.df, NTRU_PARAMS.df - 1);

    onAttempt?.(attempt, 'Computing f^(-1) mod p');
    const F_p = inverseModP(f, NTRU_PARAMS.N, NTRU_PARAMS.p);
    if (F_p === null) {
      onAttempt?.(attempt, 'f is not invertible mod p; retrying');
      continue;
    }

    onAttempt?.(attempt, 'Computing f^(-1) mod q via Hensel lifting');
    const F_q = inverseModQ(f, NTRU_PARAMS.N, NTRU_PARAMS.q);
    if (F_q === null) {
      onAttempt?.(attempt, 'f is not invertible mod q; retrying');
      continue;
    }

    onAttempt?.(attempt, 'Generating random g');
    const g = randomTernary(NTRU_PARAMS.N, NTRU_PARAMS.dg, NTRU_PARAMS.dg);

    onAttempt?.(attempt, 'Computing h = p · F_q · g mod q');
    const fqTimesG = multiply(F_q, g, NTRU_PARAMS.q);
    const publicKey = scalePoly(fqTimesG, NTRU_PARAMS.p, NTRU_PARAMS.q);

    onAttempt?.(attempt, 'Key generation complete');
    return {
      privateKey: { f, F_p },
      publicKey,
      generationAttempts: attempt,
    };
  }
}

/** Encode bytes as ternary polynomial (base-3 coding). */
export function encodeMessage(bytes: Uint8Array, N: number): Polynomial {
  const coeffsPerByte = 6;
  const needed = bytes.length * coeffsPerByte;
  if (needed > N) {
    throw new Error(`Message too long for N=${N}; need ${needed} coefficients`);
  }

  const out = new Int32Array(N);
  let idx = 0;

  for (let b = 0; b < bytes.length; b += 1) {
    let value = bytes[b];

    for (let d = 0; d < coeffsPerByte; d += 1) {
      const digit = value % 3;
      out[idx] = digit === 2 ? -1 : digit;
      value = Math.floor(value / 3);
      idx += 1;
    }
  }

  return out;
}

export function decodeMessage(m: Polynomial, originalLength: number): Uint8Array {
  const coeffsPerByte = 6;
  const needed = originalLength * coeffsPerByte;
  if (needed > m.length) {
    throw new Error('Not enough coefficients for requested byte length');
  }

  const out = new Uint8Array(originalLength);

  for (let b = 0; b < originalLength; b += 1) {
    let value = 0;
    let place = 1;

    for (let d = 0; d < coeffsPerByte; d += 1) {
      const c = m[b * coeffsPerByte + d];
      const digit = c === -1 ? 2 : modPos(c, 3);
      value += digit * place;
      place *= 3;
    }

    if (value > 255) {
      throw new Error('Decoded value exceeds byte range; likely decryption mismatch');
    }

    out[b] = value;
  }

  return out;
}

/**
 * Encrypt: e = r · h + m mod q
 * Returns ciphertext AND the blinding polynomial (for demo visibility).
 */
export function encrypt(
  m: Polynomial,
  publicKey: Polynomial,
): {
  ciphertext: Polynomial;
  blindingPoly: Polynomial;
} {
  if (m.length !== NTRU_PARAMS.N || publicKey.length !== NTRU_PARAMS.N) {
    throw new Error('Polynomial length must match NTRU parameter N');
  }

  const blindingPoly = randomTernary(
    NTRU_PARAMS.N,
    NTRU_PARAMS.dr,
    NTRU_PARAMS.dr,
  );

  const rh = multiply(blindingPoly, publicKey, NTRU_PARAMS.q);
  const mModQ = reduceMod(m, NTRU_PARAMS.q);
  const ciphertext = add(rh, mModQ, NTRU_PARAMS.q);

  return { ciphertext, blindingPoly };
}

/**
 * Decrypt:
 *   a = f · e mod q, center-reduced
 *   b = a mod p
 *   m' = F_p · b mod p
 */
export function decrypt(
  e: Polynomial,
  privateKey: { f: Polynomial; F_p: Polynomial },
): Polynomial {
  if (e.length !== NTRU_PARAMS.N) {
    throw new Error('Ciphertext length must match NTRU parameter N');
  }

  const a = centerReduce(multiply(privateKey.f, e, NTRU_PARAMS.q), NTRU_PARAMS.q);
  const b = reduceMod(a, NTRU_PARAMS.p);
  const mPrimeMod3 = multiply(privateKey.F_p, b, NTRU_PARAMS.p);

  return toBalancedMod3(mPrimeMod3);
}

/** Compare original vs recovered message, report diffs. */
export function diagnoseDecryption(
  original: Polynomial,
  recovered: Polynomial,
): {
  matches: boolean;
  differingCoefficients: number;
  totalCoefficients: number;
} {
  if (original.length !== recovered.length) {
    return {
      matches: false,
      differingCoefficients: Math.max(original.length, recovered.length),
      totalCoefficients: Math.max(original.length, recovered.length),
    };
  }

  let diffs = 0;
  for (let i = 0; i < original.length; i += 1) {
    if (original[i] !== recovered[i]) {
      diffs += 1;
    }
  }

  return {
    matches: diffs === 0,
    differingCoefficients: diffs,
    totalCoefficients: original.length,
  };
}
