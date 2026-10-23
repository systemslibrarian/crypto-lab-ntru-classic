# Changelog

All notable changes to this project are documented in this file.

## Unreleased - 2026-10-23

### Fixed
- Corrected the parameter provenance from primary publications. The coefficient shapes follow the original HPS paper (`f ∈ L(df,df−1)`, `g,r ∈ L(d,d)`), while `N=443`, `p=3`, `q=2048`, and the numeral 143 echo the official first-round NTRU-443 table. Their combination here is a demo-selected hybrid—not a published parameter set—and ePrint 2015/708's `N=443` row is product-form.
- Added regression assertions for the existing original-form weights: `f ∈ L(143,142)` and `g,r ∈ L(143,143)`. The primary-source review confirmed that changing `f` to the first-round submission's different sampler would have been wrong for this demo's equations.
- Replaced modulo-biased random index selection in the small lattice bridge with the rejection sampler used by the main implementation, and tightened integer/count validation.
- Added fail-closed validation for malformed message, public-key, ciphertext, private-key, and walkthrough polynomials at the exported crypto API boundary.
- Added shape/modulus validation to the exported inversion helpers, replaced a vacuous "known invertible" test with a real vector assertion, and stopped the 2D reducer from marking an exhausted step budget as proven success.
- Removed unsupported claims about a `2^-80` demo failure rate, 609-byte wire objects, global patent expiration, the reason NIST selected Kyber, and absolute quantum/security guarantees.
- Corrected the standards timeline from a vague 2009–2011 span to the publishers' records: IEEE 1363.1-2008 was approved in 2008 and published in 2009; ANSI X9.98-2010 dates to 2010. Their current inactive/historical status is now stated and linked.
- The tamper exercise now says explicitly that comparison against a retained plaintext is not ciphertext authentication, and its equation badges retract the previous successful verdict.
- The standalone verifier now really executes the production build and scans source files without shelling out; it no longer prints an unconditional build pass.
- GitHub Pages publishing authority is isolated from repository code, PRs retain no deployable artifact, Node 22/24/26 all gate the build, the browser-tested bundle is the one deployed, and dependency merge/dispatch failures fail closed. Seven tests enforce these workflow controls.

## Unreleased - 2026-07-12

### Added — pedagogy pass (teach the idea before the mechanism)
- Plain-language **"What is NTRU?" intro block** above Exhibit 1: states the one-sentence idea (public `h` is noise, private `f` is a short secret; anyone scrambles, only `f` unscrambles) before any algebra, and maps how the exhibits earn it.
- **Progressive equation reveal** in Exhibit 2: the four scheme equations now stay locked and dimmed until their inputs are drawn on screen, unlocking in sequence (`h` → `e` → identity → recovery), each with a per-symbol hover glossary. Message-encoding now comes first, with a note motivating `p = 3` (ternary).
- **Animated decryption pipeline** (Exhibit 2, Step 3): the real recovered polynomials flow left to right — `e → a → mod p → F_p → m'` — with a visible ±q/2 wraparound **danger zone** bar chart and a live margin readout.
- **Computed lattice bridge** (Exhibit 3, Part B): a new `src/ntru-lattice.ts` builds a genuine small NTRU keypair (`N=5, q=32`, ternary `f`/`g`, a computed inverse, and `h = p·F_q·g`), assembles its 2N-dimensional public lattice from `h` alone, and checks whether real LLL returns the target private-key vector up to symmetry. Backed by 6 new Vitest cases (52 total); the October correction above narrows the original release's broader attack claim.
- **"Why it matters" column** in the Exhibit 4 comparison table, turning each row into the tradeoff it implies (e.g. NTT-friendly `X^n+1`).

### Fixed
- **Parameter attribution changed (superseded 2026-10-23).** This release correctly removed the false `ees443ep1` label but moved the attribution to ePrint 2015/708. A later primary-source review found that paper's `N=443` row is product-form too; the October entry above records the corrected source and construction boundary.
- Removed the unsourced "decryption failures ~2^-80 for ees443ep1" figure, which hung off the same bad label; the warning now explains the ±q/2 wraparound mechanism without asserting an unverified probability. The lattice-attack note likewise points readers at the parameter-selection paper instead of quoting a bare "2^128".

### Changed
- Exhibit 1 retitled "Build the Keypair" and reframed around meeting `f` and `h`, with an interpretive note on why small-coefficient `f` looks unlike mod-q `h`.
- Locked-equation styling signals state via badge, dashed border and background (never lowered text opacity), preserving WCAG AA contrast in the axe gate.

## v1.1.0 - 2026-06-24

### Added
- Live Gauss–Lagrange lattice reduction in Exhibit 3 (replaces the previous scripted 3-frame animation). Each step is computed: swap, size-reduce, shrinking norms, constant determinant, and convergence to a shortest vector. Includes step, auto-reduce, and random-new-basis controls.
- Decryption walkthrough in Exhibit 2: a collapsible, step-by-step view with live intermediate values that verifies the identity `f · e ≡ p·r·g + f·m (mod q)` and reports the per-ciphertext decryption margin.
- KaTeX math typesetting for the scheme equations and walkthrough (accessible MathML output).
- Per-coefficient ring inspection on hover, plus color legends for the ring visualizations.
- Vitest test suite (46 tests) covering polynomial arithmetic, inversion, encode/decode, round-trips, the decryption identity, lattice reduction (200-case fuzz), and a headless DOM smoke test of the full UI flow.
- Two new verification gates (11: Gauss reduction is reduced and determinant-invariant; 12: decryption identity holds) and a pass/fail summary; `verify` now exits non-zero on failure.
- CI now runs `npm test` and `npm run verify` before building for deploy.

### Changed
- `modPos` now normalizes `-0` to `+0` so it never reaches coefficient arrays.
- `generateKeyPair` exposes `g` (documented as a teaching artifact only; not required to decrypt).
- Upgraded Vite to resolve a high-severity advisory.

### Removed
- Leftover Vite scaffolding: `counter.ts`, unused assets (`hero.png`, `typescript.svg`, `vite.svg`), and the unused `public/icons.svg`.

## v1.0.0 - 2026-04-19

### Added
- Full educational NTRU Classic (1996) browser implementation with ees443ep1 parameters.
- Polynomial arithmetic in Z[X]/(X^N - 1), including convolution and modular reduction.
- Inversion mod 3 and mod 2048 (Hensel lifting) for NTRU key generation.
- NTRU keygen/encrypt/decrypt core with retry visibility for non-invertible f.
- Five-exhibit interactive UI including ring visualizations and lattice intuition demo.
- Verification script at scripts/verify.ts with 10 project gates.

### Accessibility and UX (Phases 8-10)
- ADA and WCAG refinements: skip link, live regions, semantic table improvements, focus-visible states.
- Mobile responsiveness improvements: stacked controls, horizontal table overflow handling, touch-friendly controls.
- Message-length guard and byte-usage helper for encoding constraints.
- Tamper-ciphertext demonstration integrated in UI.
- Better action-state controls (disabled states, busy feedback, reset behavior on key regeneration).
- Ring rendering micro-optimization for per-coefficient center reduction.

### Security/Correctness Notes
- Randomness uses crypto.getRandomValues (no Math.random in src).
- The release labelled its `N=443, p=3, q=2048` profile as ees443ep1; that historical label was corrected in later entries above.
- 100-round encryption/decryption verification passes with 0 failures in current checks.
