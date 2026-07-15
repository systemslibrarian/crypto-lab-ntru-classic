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

It is built for two audiences at once. A newcomer gets a plain-language on-ramp — a "What is NTRU?" intro that states the one-sentence idea before any algebra, a message-encoding-first Exhibit 2 whose four equations stay locked and dimmed until the objects they describe are drawn on screen, and an animated decryption pipeline with a visible ±q/2 wraparound danger zone. A professional gets the load-bearing details kept honest: a real (not asserted) lattice attack that builds a genuine small NTRU keypair, assembles its 2N-dimensional public lattice from `h` alone, and runs real LLL that recovers the private key as the lattice's short vector — up to the true rotation/sign symmetry of the scheme.

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

A short **"What is NTRU?" intro** opens the page above Exhibit 1, stating the one-sentence idea — the public key `h` looks like noise, the private key `f` is a secret *short* pattern, and only someone who knows `f` can cleanly unscramble — before any math, then mapping how the exhibits earn the algebra.

1. **Build the keypair** — watch the retry loop discard non-invertible `f`, with ring visualizations of the public key `h` and (censored) private key `f`, and a side-by-side reading of *why* the short/sparse `f` looks nothing like the noisy `h` that multiplying and inverting mod `q` produces.
2. **Encrypt and decrypt** — message-encoding first: encode a string to a **ternary** polynomial (with a note motivating `p = 3`), then encrypt, decrypt, and tamper. The four scheme equations are typeset with KaTeX but stay **locked and dimmed until their inputs appear on screen**, unlocking in sequence (`h` → `e` → identity → recovery), each with a hover glossary for every symbol. An animated **decryption pipeline** flows the real polynomials left to right — `e → a` (with a visible ±q/2 wraparound **danger zone**) → `mod p` → `F_p` → `m'` — and a collapsible **walkthrough** shows the algebra with live values, a verified `f · e ≡ p·r·g + f·m (mod q)` identity check, and the per-ciphertext decryption margin before wraparound. Hovering any ring reveals individual coefficients.
3. **The lattice perspective** — *Part A* is a live, honest **Gauss–Lagrange reduction** of a 2D lattice (the exact analogue of LLL): step or auto-run it; the basis vectors shrink onto a fixed lattice while the determinant stays invariant and `b₁` converges to a shortest vector. *Part B* is the **bridge**: a genuine, fully worked small NTRU key (real ternary `f`, `g`, a real inverse, real `h = p·F_q·g` at `N=5, q=32`), its true 10-dimensional public lattice built only from `h`, and a real LLL **Attack** that recovers the private key as the short vector — proving "breaking NTRU = finding the short vector" instead of asserting it.
4. **NTRU Classic vs ML-KEM-768** — a comparison table, now with a **"why it matters"** column that turns each row into the tradeoff it implies (e.g. why Kyber's NTT-friendly `X^n+1` ring is faster).
5. **Historical impact and patent story** — a timeline.

## Development

```sh
npm install      # install dependencies
npm run dev      # local dev server
npm test         # Vitest unit + DOM smoke tests (52 tests)
npm run verify   # 12 project verification gates
npm run build    # type-check and production build
```

Correctness is guarded by a Vitest suite (polynomial arithmetic, inversion, encode/decode, encrypt/decrypt round-trips, the decryption identity, Gauss reduction with a 200-case fuzz, and the small-instance lattice bridge — which re-verifies `f · h ≡ p·g (mod q)` and that LLL's short vector really is the key across many random instances) plus a headless DOM smoke test that drives the full generate → encrypt → decrypt flow. CI runs the tests and verification gates before every GitHub Pages deploy, and an axe-core WCAG 2.1 AA gate scans both themes.

---

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
