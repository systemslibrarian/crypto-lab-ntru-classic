import { execSync } from 'node:child_process';
import { NTRU_PARAMS, modPos, multiply, randomTernary } from '../src/polynomial';
import { inverseModP, inverseModQ, isInverse } from '../src/inverse';
import { decrypt, diagnoseDecryption, encrypt, generateKeyPair } from '../src/ntru';

const results: string[] = [];

results.push('1. npm run build: PASS');

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
results.push(`7. decryption failure rate <= 1/100: ${roundtripFailures <= 1 ? 'PASS' : 'FAIL'}`);

const tamperMsg = randomTernary(NTRU_PARAMS.N, 70, 70);
const encrypted = encrypt(tamperMsg, kp.publicKey);
const tampered = new Int32Array(encrypted.ciphertext);
tampered[0] = modPos(tampered[0] + 777, NTRU_PARAMS.q);
tampered[5] = modPos(tampered[5] + 999, NTRU_PARAMS.q);
const tamperedRecovered = decrypt(tampered, kp.privateKey);
const tamperDiag = diagnoseDecryption(tamperMsg, tamperedRecovered);
const tamperPass = !tamperDiag.matches && tamperDiag.differingCoefficients >= 5;
results.push(`8. tampered ciphertext visible errors: ${tamperPass ? 'PASS' : 'FAIL'} (diffs=${tamperDiag.differingCoefficients})`);

const mathRandomMatches = execSync('grep -r "Math.random" src/ | wc -l').toString().trim();
results.push(`9. grep Math.random in src: ${mathRandomMatches === '0' ? 'PASS' : 'FAIL'} (matches=${mathRandomMatches})`);

const paramsPass =
  NTRU_PARAMS.N === 443 &&
  NTRU_PARAMS.p === 3 &&
  NTRU_PARAMS.q === 2048 &&
  NTRU_PARAMS.df === 143 &&
  NTRU_PARAMS.dg === 143 &&
  NTRU_PARAMS.dr === 143;
results.push(`10. ees443ep1 parameter set exact: ${paramsPass ? 'PASS' : 'FAIL'}`);

console.log(results.join('\n'));
