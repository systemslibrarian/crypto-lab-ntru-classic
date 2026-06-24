import { describe, expect, it } from 'vitest';
import {
  decodeMessage,
  decrypt,
  diagnoseDecryption,
  encodeMessage,
  encrypt,
  explainDecryption,
  generateKeyPair,
} from '../src/ntru';
import { NTRU_PARAMS, modPos, randomTernary } from '../src/polynomial';

describe('encodeMessage / decodeMessage', () => {
  it('round-trips arbitrary byte values through base-3 coding', () => {
    const bytes = new Uint8Array([0, 1, 42, 128, 255]);
    const poly = encodeMessage(bytes, NTRU_PARAMS.N);
    const back = decodeMessage(poly, bytes.length);
    expect(Array.from(back)).toEqual(Array.from(bytes));
  });

  it('encodes into balanced-ternary coefficients only ({-1,0,1})', () => {
    const poly = encodeMessage(new Uint8Array([255, 17, 200]), NTRU_PARAMS.N);
    for (const c of poly) expect([-1, 0, 1]).toContain(c);
  });

  it('round-trips a UTF-8 string', () => {
    const text = 'Hello, NTRU 1996!';
    const bytes = new TextEncoder().encode(text);
    const poly = encodeMessage(bytes, NTRU_PARAMS.N);
    const recovered = new TextDecoder().decode(decodeMessage(poly, bytes.length));
    expect(recovered).toBe(text);
  });

  it('throws when the message is too long for N', () => {
    const tooLong = new Uint8Array(Math.floor(NTRU_PARAMS.N / 6) + 1);
    expect(() => encodeMessage(tooLong, NTRU_PARAMS.N)).toThrow();
  });
});

describe('generateKeyPair', () => {
  it('reports a positive attempt count and emits progress callbacks', () => {
    const reasons: string[] = [];
    const kp = generateKeyPair((_, reason) => reasons.push(reason));
    expect(kp.generationAttempts).toBeGreaterThanOrEqual(1);
    expect(kp.publicKey.length).toBe(NTRU_PARAMS.N);
    expect(kp.privateKey.f.length).toBe(NTRU_PARAMS.N);
    expect(reasons.some((r) => r.includes('Key generation complete'))).toBe(true);
  });
});

describe('encrypt / decrypt round-trip', () => {
  it('recovers the message exactly across many random trials', () => {
    const kp = generateKeyPair();
    let failures = 0;
    for (let i = 0; i < 50; i += 1) {
      const m = randomTernary(NTRU_PARAMS.N, 80, 80);
      const { ciphertext } = encrypt(m, kp.publicKey);
      const recovered = decrypt(ciphertext, kp.privateKey);
      if (!diagnoseDecryption(m, recovered).matches) failures += 1;
    }
    expect(failures).toBe(0);
  });

  it('recovers an actual text message end to end', () => {
    const kp = generateKeyPair();
    const text = 'lattice';
    const bytes = new TextEncoder().encode(text);
    const m = encodeMessage(bytes, NTRU_PARAMS.N);
    const { ciphertext } = encrypt(m, kp.publicKey);
    const recovered = decrypt(ciphertext, kp.privateKey);
    expect(diagnoseDecryption(m, recovered).matches).toBe(true);
    expect(new TextDecoder().decode(decodeMessage(recovered, bytes.length))).toBe(text);
  });

  it('rejects polynomials whose length is not N', () => {
    const kp = generateKeyPair();
    expect(() => encrypt(new Int32Array(10), kp.publicKey)).toThrow();
    expect(() => decrypt(new Int32Array(10), kp.privateKey)).toThrow();
  });
});

describe('diagnoseDecryption / tamper sensitivity', () => {
  it('flags a mismatch and counts differing coefficients', () => {
    const a = new Int32Array([1, 0, -1, 1]);
    const b = new Int32Array([1, 1, -1, 0]);
    const d = diagnoseDecryption(a, b);
    expect(d.matches).toBe(false);
    expect(d.differingCoefficients).toBe(2);
    expect(d.totalCoefficients).toBe(4);
  });

  it('confirms the identity f·e ≡ p·r·g + f·m (mod q) on a real round-trip', () => {
    const kp = generateKeyPair();
    const m = randomTernary(NTRU_PARAMS.N, 80, 80);
    const { ciphertext, blindingPoly } = encrypt(m, kp.publicKey);
    const w = explainDecryption(ciphertext, kp.privateKey, { r: blindingPoly, g: kp.g, m });

    expect(w.identityHolds).toBe(true);
    expect(Array.from(w.recovered)).toEqual(Array.from(m));
    // A correct decryption must keep the lift strictly inside the (-q/2, q/2] window.
    expect(w.maxLiftCoeff).toBeLessThan(NTRU_PARAMS.q / 2);
    expect(w.decryptionMargin).toBeGreaterThan(0);
  });
});

describe('ciphertext tamper sensitivity', () => {
  it('produces visibly corrupted output when the ciphertext is tampered', () => {
    const kp = generateKeyPair();
    const m = randomTernary(NTRU_PARAMS.N, 70, 70);
    const { ciphertext } = encrypt(m, kp.publicKey);
    const tampered = new Int32Array(ciphertext);
    tampered[0] = modPos(tampered[0] + 777, NTRU_PARAMS.q);
    tampered[5] = modPos(tampered[5] + 999, NTRU_PARAMS.q);
    const recovered = decrypt(tampered, kp.privateKey);
    const d = diagnoseDecryption(m, recovered);
    expect(d.matches).toBe(false);
    expect(d.differingCoefficients).toBeGreaterThanOrEqual(5);
  });
});
