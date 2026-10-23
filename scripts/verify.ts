import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { NTRU_PARAMS, modPos, multiply, randomTernary } from '../src/polynomial';
import { inverseModP, inverseModQ, isInverse } from '../src/inverse';
import {
  decrypt,
  diagnoseDecryption,
  encrypt,
  explainDecryption,
  generateKeyPair,
} from '../src/ntru';
import { gaussReduce, norm2, randomBadBasis } from '../src/lattice';

const results: string[] = [];

const npmCommand = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const build = spawnSync(npmCommand, ['run', 'build'], { encoding: 'utf8' });
const buildPass = build.status === 0;
if (!buildPass) {
  process.stderr.write(build.stdout);
  process.stderr.write(build.stderr);
}
results.push(`1. npm run build executed: ${buildPass ? 'PASS' : 'FAIL'}`);

const a = new Int32Array([1, 2, 0, 0]);
const b = new Int32Array([0, 1, 1, 0]);
const conv = multiply(a, b, 97);
const expected = [0, 1, 3, 2];
const convPass = expected.every((v, i) => conv[i] === v);
results.push(`2. convolution reference test: ${convPass ? 'PASS' : 'FAIL'} (${Array.from(conv).slice(0, 4).join(',')})`);

let f: Int32Array | null = null;
let Fp: Int32Array | null = null;
for (let i = 0; i < 32; i += 1) {
  const candidate = randomTernary(NTRU_PARAMS.N, NTRU_PARAMS.df, NTRU_PARAMS.df - 1);
  const maybeFp = inverseModP(candidate, NTRU_PARAMS.N, NTRU_PARAMS.p);
  if (maybeFp) {
    f = candidate;
    Fp = maybeFp;
    break;
  }
}

const inv3Pass = !!f && !!Fp && isInverse(f, Fp, NTRU_PARAMS.N, NTRU_PARAMS.p);
results.push(`3. inverse mod 3 verify: ${inv3Pass ? 'PASS' : 'FAIL'}`);

let Fq: Int32Array | null = null;
if (f) {
  Fq = inverseModQ(f, NTRU_PARAMS.N, NTRU_PARAMS.q);
}
const invQPass = !!f && !!Fq && isInverse(f, Fq, NTRU_PARAMS.N, NTRU_PARAMS.q);
results.push(`4. inverse mod 2048 (Hensel) verify: ${invQPass ? 'PASS' : 'FAIL'}`);

const kp = generateKeyPair();
results.push(`5. key generation retry counter available: ${kp.generationAttempts >= 1 ? 'PASS' : 'FAIL'} (attempts=${kp.generationAttempts})`);

let roundtripFailures = 0;
for (let i = 0; i < 100; i += 1) {
  const msg = randomTernary(NTRU_PARAMS.N, 80, 80);
  const { ciphertext } = encrypt(msg, kp.publicKey);
  const recovered = decrypt(ciphertext, kp.privateKey);
  if (!diagnoseDecryption(msg, recovered).matches) {
    roundtripFailures += 1;
  }
}
results.push(`6. 100 round-trips random messages: ${roundtripFailures === 0 ? 'PASS' : 'FAIL'} (failures=${roundtripFailures})`);
const count = (poly: Int32Array, coefficient: number): number =>
  Array.from(poly).filter((value) => value === coefficient).length;
const profilePass =
  count(kp.privateKey.f, 1) === NTRU_PARAMS.df &&
  count(kp.privateKey.f, -1) === NTRU_PARAMS.df - 1 &&
  count(kp.g, 1) === NTRU_PARAMS.dg &&
  count(kp.g, -1) === NTRU_PARAMS.dg;
results.push(`7. f∈L(df,df−1) and g∈L(dg,dg): ${profilePass ? 'PASS' : 'FAIL'}`);

const tamperMsg = randomTernary(NTRU_PARAMS.N, 70, 70);
const encrypted = encrypt(tamperMsg, kp.publicKey);
const tampered = new Int32Array(encrypted.ciphertext);
tampered[0] = modPos(tampered[0] + 777, NTRU_PARAMS.q);
tampered[5] = modPos(tampered[5] + 999, NTRU_PARAMS.q);
const tamperedRecovered = decrypt(tampered, kp.privateKey);
const tamperDiag = diagnoseDecryption(tamperMsg, tamperedRecovered);
const tamperPass = !tamperDiag.matches && tamperDiag.differingCoefficients >= 5;
results.push(`8. raw ciphertext corruption changes recovery: ${tamperPass ? 'PASS' : 'FAIL'} (diffs=${tamperDiag.differingCoefficients})`);

function countSourceText(directory: string, needle: string): number {
  let matches = 0;
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = `${directory}/${entry.name}`;
    if (entry.isDirectory()) {
      matches += countSourceText(path, needle);
    } else if (entry.isFile()) {
      matches += readFileSync(path, 'utf8').split(needle).length - 1;
    }
  }
  return matches;
}

const srcDirectory = fileURLToPath(new URL('../src/', import.meta.url));
const mathRandomMatches = countSourceText(srcDirectory, 'Math.random');
results.push(`9. no Math.random in src: ${mathRandomMatches === 0 ? 'PASS' : 'FAIL'} (matches=${mathRandomMatches})`);

const paramsPass =
  NTRU_PARAMS.N === 443 &&
  NTRU_PARAMS.p === 3 &&
  NTRU_PARAMS.q === 2048 &&
  NTRU_PARAMS.df === 143 &&
  NTRU_PARAMS.dg === 143 &&
  NTRU_PARAMS.dr === 143;
results.push(`10. educational NTRU profile values exact: ${paramsPass ? 'PASS' : 'FAIL'}`);

let latticePass = true;
for (let i = 0; i < 200; i += 1) {
  const { b1, b2 } = randomBadBasis();
  const det0 = Math.abs(b1.x * b2.y - b1.y * b2.x);
  const trace = gaussReduce(b1, b2);
  const final = trace[trace.length - 1];
  const detF = Math.abs(final.b1.x * final.b2.y - final.b1.y * final.b2.x);
  if (norm2(final.b1) > norm2(final.b2) + 1e-9 || Math.abs(detF - det0) > 1e-6 || !final.done) {
    latticePass = false;
    break;
  }
}
results.push(`11. Gauss reduction reduced + determinant-invariant (200 fuzz): ${latticePass ? 'PASS' : 'FAIL'}`);

const wMsg = randomTernary(NTRU_PARAMS.N, 80, 80);
const wEnc = encrypt(wMsg, kp.publicKey);
const w = explainDecryption(wEnc.ciphertext, kp.privateKey, {
  r: wEnc.blindingPoly,
  g: kp.g,
  m: wMsg,
});
const identityPass = w.identityHolds && w.decryptionMargin > 0;
results.push(`12. decryption identity f·e ≡ p·r·g + f·m holds (margin=${w.decryptionMargin}): ${identityPass ? 'PASS' : 'FAIL'}`);

const gateCount = results.length;
const allPass = results.every((line) => !line.includes('FAIL'));
results.push('');
results.push(`Summary: ${allPass ? 'ALL GATES PASS' : 'FAILURES PRESENT'} (${gateCount} gates)`);

console.log(results.join('\n'));

if (!allPass) {
  process.exitCode = 1;
}
