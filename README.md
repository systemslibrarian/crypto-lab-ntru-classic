# crypto-lab-ntru-classic

## What It Is

Browser-based educational demo of the original Hoffstein-Pipher-Silverman NTRU equations at `N = 443`, `p = 3`, `q = 2048`, and demo-selected weights `df = dg = dr = 143`. It is a raw teaching construction, not a published parameter set or a submitted/standardized NTRU PKE/KEM, and it claims no production security level.

The code uses the original-style public-key equation `h = p · f⁻¹ · g (mod q)` with these fixed-weight distributions:

- N = 443
- p = 3
- q = 2048
- df = dg = dr = 143
- `f ∈ L(df, df − 1)`: 143 coefficients are +1 and 142 are −1
- `g ∈ L(dg, dg)` and `r ∈ L(dr, dr)`: 143 coefficients of each sign

The coefficient shapes come from the [original HPS paper](https://www.ntru.org/f/hps98.pdf), which defines `L_f = L(df, df − 1)`, `L_g = L(dg, dg)`, and the blinding space `L_φ = L(d, d)`. The demo itself chooses 143 for all three weights. Its `N = 443`, `p = 3`, `q = 2048` scale and the numeral 143 echo NTRU-443 in Table 1 of the official [first-round NTRUEncrypt supporting package](https://www.ntru.org/f/NTRUEncrypt.zip), but combining those values with the original equations is an educational hybrid—not the published NTRU-443 profile.

The submitted scheme used `h = g/(p f + 1)`, padding, message masking, deterministic coins, and decrypt-and-verify rejection; this demo instead uses the raw equation above, a custom six-trit byte encoding, fresh random `r`, and no ciphertext validation. Its security and decryption-failure estimates therefore do not transfer.

Earlier revisions first mislabeled the profile as EESS#1 `ees443ep1`, then incorrectly moved the attribution to [ePrint 2015/708](https://eprint.iacr.org/2015/708). Neither is the source of this flat profile: `ees443ep1` is product-form, and the paper's `N = 443` row uses `(d1, d2, d3, dg, dm) = (9, 8, 5, 148, 115)`. No security or decryption-failure estimate from either construction applies to this demo.

All polynomial arithmetic is implemented from scratch with `Int32Array` coefficients in the ring `Z[X]/(X^N - 1)`, including:

- cyclic convolution multiplication
- inversion modulo 3 via polynomial extended Euclidean algorithm
- inversion modulo 2048 via Hensel lifting from mod 2

The demo explicitly shows probabilistic key generation retries when `f` is not invertible, then walks through encryption and decryption using:

`f · e ≡ p·r·g + f·m (mod q)`

It is built for two audiences at once. A newcomer gets a plain-language on-ramp, a message-encoding-first Exhibit 2 whose four equations unlock only when their objects exist, and an animated decryption pipeline with a visible ±q/2 wraparound danger zone. A professional gets the construction boundary stated explicitly and a computed small-instance lattice exercise: it builds a genuine tiny NTRU keypair, assembles its 2N-dimensional public lattice from `h` alone, and checks whether real LLL recovers a useful private-key vector up to rotation and sign.

## When to Use It

- understand the origin of lattice public-key cryptography
- learn polynomial ring arithmetic behind post-quantum schemes
- compare original NTRU design choices with modern ML-KEM (Kyber)
- teach why short-vector problems became central in PQC
- Do NOT use this as production cryptography — it is a teaching demo; for standardized KEM deployment, use ML-KEM implementations.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-ntru-classic](https://systemslibrarian.github.io/crypto-lab-ntru-classic/)**

The demo runs its raw NTRU teaching flow in the browser: watch probabilistic key generation discard non-invertible `f`, encode a string to a ternary polynomial, then encrypt, decrypt, and corrupt a ciphertext. A collapsible walkthrough verifies `f · e ≡ p·r·g + f·m (mod q)` with live values and makes clear that corruption is recognized only because the page retained the original plaintext. A live Gauss–Lagrange 2D reduction, a tiny computed NTRU lattice, a construction-aware ML-KEM-768 comparison, and a historical timeline round out the exhibits.

## What Can Go Wrong

- This raw profile can suffer decryption failure when a coefficient of `p·r·g + f·m` crosses the ±q/2 window. The demo has no derived failure bound; 100 passing trials are only a regression check.
- Key generation is probabilistic; some candidate `f` values are discarded.
- This TypeScript demo is not constant-time and can leak timing structure.
- The raw ciphertext has no authentication or standalone integrity check. The tamper exercise can report a difference only because the page retained the original plaintext.
- The hybrid profile does not carry over NTRU-443's security estimate because the construction, distributions, encoding, and validation behavior differ.
- Do not assign this code an IND-CPA or IND-CCA label without a proof for its exact construction. It intentionally omits the transforms and validation used by deployable schemes.

## Real-World Usage

- NTRU was introduced in 1996 by Jeffrey Hoffstein, Jill Pipher, and Joseph Silverman at Brown University.
- 1996–1998: invention, CRYPTO rump-session presentation, and ANTS-III publication.
- 2007: NIST's third-round report records the NTRU US patents as dedicated to the public.
- 2008–2009: [IEEE 1363.1-2008](https://standards.ieee.org/ieee/4/3074/) was approved and published; IEEE now lists it as inactive-reserved.
- 2010: [ANSI X9.98-2010](https://webstore.ansi.org/standards/ascx9/ANSIX9982010) specified lattice-based polynomial public-key establishment for financial services; the store lists it as historical and reaffirmed in 2017.
- 2017–2022: NTRU entered the NIST PQC process, advanced as a third-round finalist, and was not selected after round three. NIST identified key-generation performance as a significant selection factor and noted more security evidence for structured Module-LWE.
- 2024: ML-KEM (Kyber) standardized as FIPS 203. NTRU remains historically foundational and pedagogically important for understanding modern lattice cryptography.

See [NIST IR 8413-upd1](https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=935591) for the selection and patent-history statements, and [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) for ML-KEM.

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

A short **"What is NTRU?" intro** opens the page above Exhibit 1: public `h` looks noisy, private `f` is short, and `f` supplies the trapdoor that reverses the public scrambling operation.

1. **Build the keypair** — watch the retry loop discard non-invertible `f`, with ring visualizations of public `h` and private `f`. The page gives the exact 143/142/158 coefficient profile rather than incorrectly calling `f` sparse.
2. **Encrypt and decrypt** — message-encoding first: encode a string to a **ternary** polynomial (with a note motivating `p = 3`), then encrypt, decrypt, and tamper. The four scheme equations are typeset with KaTeX but stay **locked and dimmed until their inputs appear on screen**, unlocking in sequence (`h` → `e` → identity → recovery), each with a hover glossary for every symbol. An animated **decryption pipeline** flows the real polynomials left to right — `e → a` (with a visible ±q/2 wraparound **danger zone**) → `mod p` → `F_p` → `m'` — and a collapsible **walkthrough** shows the algebra with live values, a verified `f · e ≡ p·r·g + f·m (mod q)` identity check, and the per-ciphertext decryption margin before wraparound. Hovering any ring reveals individual coefficients.
3. **The lattice perspective** — *Part A* is a live **Gauss–Lagrange reduction** of a 2D lattice: the basis shrinks while its determinant remains invariant. *Part B* builds a genuine small NTRU key (`N=5, q=32`), its true 10-dimensional public lattice from `h` alone, and runs LLL to test recovery of an equivalent short private-key vector.
4. **Raw NTRU teaching profile vs ML-KEM-768** — a comparison table that distinguishes an in-memory teaching construction from a standardized byte-level KEM.
5. **Historical impact and patent story** — a timeline.

## Development

```sh
npm install      # install dependencies
npm run dev      # local dev server
npm test         # Vitest unit + DOM smoke tests (60 tests)
npm run verify   # 12 project verification gates
npm run build    # type-check and production build
```

Correctness is guarded by Vitest (polynomial arithmetic, fixed-weight sampling, malformed-input rejection, inversion, encode/decode, encrypt/decrypt round-trips, the decryption identity, Gauss reduction fuzzing, and the small-instance lattice bridge) plus browser behavior and axe-core WCAG 2.1 A/AA gates. CI runs unit and production-build controls on Node 22, 24, and 26, isolates Pages authority from jobs that execute repository code, and publishes only the exact bundle retained by the successful browser job.

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
