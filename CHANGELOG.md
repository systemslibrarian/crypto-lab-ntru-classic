# Changelog

All notable changes to this project are documented in this file.

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
- ees443ep1 parameters pinned exactly: N=443, p=3, q=2048, df=143, dg=143, dr=143.
- 100-round encryption/decryption verification passes with 0 failures in current checks.
