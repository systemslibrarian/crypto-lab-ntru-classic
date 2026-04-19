# crypto-lab-ntru-classic

Browser-based NTRU demo implementing the original 1996 Hoffstein-Pipher-Silverman lattice cryptosystem with EESS#1 v3.3 ees443ep1 parameters.

## What It Is

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

Use this lab when you want to:

- understand the origin of lattice public-key cryptography
- learn polynomial ring arithmetic behind post-quantum schemes
- compare original NTRU design choices with modern ML-KEM (Kyber)
- teach why short-vector problems became central in PQC

Do not use this as production cryptography. For standardized KEM deployment, use ML-KEM implementations.

## Live Demo

https://systemslibrarian.github.io/crypto-lab-ntru-classic/

## What Can Go Wrong

- Decryption failures are possible (rare, around 2^-80 for ees443ep1).
- Key generation is probabilistic; some candidate `f` values are discarded.
- This TypeScript demo is not constant-time and can leak timing structure.
- Parameter choice matters; weaker historical parameter sets are no longer secure.
- Classical NTRU is IND-CPA. Modern KEMs add transforms (for example FO-style) for IND-CCA security.

## Real-World Usage

NTRU was introduced in 1996 by Jeffrey Hoffstein, Jill Pipher, and Joseph Silverman at Brown University.

Historical milestones:

- 1996: invention and CRYPTO rump presentation
- 1998: ANTS-III publication
- 2009: IEEE P1363.1 standardization
- 2011: ANSI X9.98 adoption in finance
- 2017: US patent expiration
- 2020: NIST PQC finalist
- 2024: ML-KEM (Kyber) standardized as FIPS 203

NTRU remains historically foundational and pedagogically important for understanding modern lattice cryptography.
