# crypto-lab-ntru-classic

## What It Is

Browser-based NTRU demo implementing the original 1996 Hoffstein-Pipher-Silverman lattice cryptosystem with EESS#1 v3.3 ees443ep1 parameters.

This project is a browser-based educational implementation of NTRU Classic using the original scheme family described by Hoffstein, Pipher, and Silverman, with ees443ep1 parameters:

- N = 443
- p = 3
- q = 2048
- df = 143
- dg = 143
- dr = 143

All polynomial arithmetic is implemented from scratch with `Int32Array` coefficients in the ring `Z[X]/(X^N - 1)`, including:

- cyclic convolution multiplication
- inversion modulo 3 via polynomial extended Euclidean algorithm
- inversion modulo 2048 via Hensel lifting from mod 2

The demo explicitly shows probabilistic key generation retries when `f` is not invertible, then walks through encryption and decryption using:

`f · e ≡ p·r·g + f·m (mod q)`

## When to Use It

- understand the origin of lattice public-key cryptography
- learn polynomial ring arithmetic behind post-quantum schemes
- compare original NTRU design choices with modern ML-KEM (Kyber)
- teach why short-vector problems became central in PQC
- Do NOT use this as production cryptography — it is a teaching demo; for standardized KEM deployment, use ML-KEM implementations.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-ntru-classic](https://systemslibrarian.github.io/crypto-lab-ntru-classic/)**

The demo runs the full NTRU Classic flow in the browser: watch probabilistic key generation discard non-invertible `f`, encode a string to a ternary polynomial, then encrypt, decrypt, and tamper, with a collapsible decryption walkthrough that typesets the algebra and verifies the `f · e ≡ p·r·g + f·m (mod q)` identity with live values. A live Gauss–Lagrange 2D lattice reduction (the analogue of LLL), a comparison table against ML-KEM-768, and a historical timeline round out the exhibits.

## What Can Go Wrong

- Decryption failures are possible (rare, around 2^-80 for ees443ep1).
- Key generation is probabilistic; some candidate `f` values are discarded.
- This TypeScript demo is not constant-time and can leak timing structure.
- Parameter choice matters; weaker historical parameter sets are no longer secure.
- Classical NTRU is IND-CPA. Modern KEMs add transforms (for example FO-style) for IND-CCA security.

## Real-World Usage

- NTRU was introduced in 1996 by Jeffrey Hoffstein, Jill Pipher, and Joseph Silverman at Brown University.
- 1996–1998: invention, CRYPTO rump-session presentation, and ANTS-III publication.
- 2009–2011: IEEE P1363.1 standardization and ANSI X9.98 adoption in finance.
- 2017: US patent expiration; 2020: NIST PQC finalist.
- 2024: ML-KEM (Kyber) standardized as FIPS 203. NTRU remains historically foundational and pedagogically important for understanding modern lattice cryptography.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-ntru-classic
cd crypto-lab-ntru-classic
npm install
npm run dev
```

## Related Demos

- [crypto-lab-kyber-vault](https://systemslibrarian.github.io/crypto-lab-kyber-vault/) — ML-KEM (FIPS 203), the standardized lattice KEM NTRU is compared against.
- [crypto-lab-falcon-seal](https://systemslibrarian.github.io/crypto-lab-falcon-seal/) — FN-DSA signatures built on NTRU lattices and FFT sampling.
- [crypto-lab-frodo-vault](https://systemslibrarian.github.io/crypto-lab-frodo-vault/) — conservative LWE lattice KEM without ring structure.
- [crypto-lab-pq-families](https://systemslibrarian.github.io/crypto-lab-pq-families/) — overview of the five post-quantum cryptographic families.

## Exhibits

1. **Probabilistic key generation** — watch the retry loop discard non-invertible `f`, with ring visualizations of the public key `h` and (censored) private key `f`.
2. **Encrypt and decrypt** — encode a string to a ternary polynomial, encrypt, decrypt, and tamper. A collapsible **decryption walkthrough** shows the algebra step by step with live values, including a verified `f · e ≡ p·r·g + f·m (mod q)` identity check and the per-ciphertext decryption margin before wraparound. Equations are typeset with KaTeX, and hovering any ring reveals individual coefficients.
3. **The lattice perspective** — a live, honest **Gauss–Lagrange reduction** of a 2D lattice (the exact analogue of LLL). Step through it or auto-run it; the basis vectors shrink onto a fixed lattice while the determinant stays invariant, and `b₁` converges to a shortest vector. "New Basis" generates a fresh random bad basis.
4. **NTRU Classic vs ML-KEM-768** — a comparison table.
5. **Historical impact and patent story** — a timeline.

## Development

```sh
npm install      # install dependencies
npm run dev      # local dev server
npm test         # Vitest unit + DOM smoke tests (46 tests)
npm run verify   # 12 project verification gates
npm run build    # type-check and production build
```

Correctness is guarded by a Vitest suite (polynomial arithmetic, inversion, encode/decode, encrypt/decrypt round-trips, the decryption identity, and Gauss reduction with a 200-case fuzz) plus a headless DOM smoke test that drives the full generate → encrypt → decrypt flow. CI runs the tests and verification gates before every GitHub Pages deploy.

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
