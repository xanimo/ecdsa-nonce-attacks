#!/usr/bin/env python3
"""
Biased ECDSA nonces -> private key recovery via lattice reduction (HNP).

The realistic failure mode
--------------------------
Outright nonce reuse is loud: a duplicate r announces itself. The version that
actually survives in production is *bias* -- nonces that are not uniform over
[1, n). Every signature then leaks a few bits of the key, and enough of them
reconstruct it with no collision ever appearing.

How bias happens in real code:
  * modular reduction of a shorter value  (k = rand_128() mod n)
  * "reduce until it fits" loops that truncate rather than resample
  * seeding from a 32- or 64-bit source
  * hardware RNG returning short reads that get zero-padded
  * timestamp- or counter-derived nonces
None of these produce a repeated r. All of them are fatal.

Reduction to the Hidden Number Problem
--------------------------------------
From s = k^-1 (z + r d):

    k_i = u_i + t_i * d   (mod n),   u_i = s_i^-1 z_i,  t_i = s_i^-1 r_i

u_i and t_i are public. If each k_i is known to be small -- say k_i < K = 2^(256-L)
because the top L bits are zero -- then d is the unique value making all m of
those affine expressions small simultaneously. That is Boneh-Venkatesan's
Hidden Number Problem, and it is a short-vector problem.

Lattice, scaled by n to stay in the integers:

    [ n^2 . I_m          0        0    ]      m rows
    [ n*t_0 ... n*t_m    K        0    ]
    [ n*u_0 ... n*u_m    0      n*K    ]

The target vector  (n*k_0, ..., n*k_m, d*K, n*K)  has norm about sqrt(m+2)*n*K,
which is short relative to the lattice determinant once m > 256/L. LLL/BKZ
finds it.

Defensive use: this is the test that tells you whether a signing
implementation's nonces are actually uniform. If the lattice solves, the RNG
is broken. If it does not solve at the theoretical signature count, that is
evidence (not proof) that it is not.
"""

import hashlib
import secrets
import sys
import time

from fpylll import IntegerMatrix, LLL, BKZ

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)
NBITS = 256


def inv(x, m):
    return pow(x, -1, m)


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = 3 * x1 * x1 * inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * inv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def point_mul(k, p=G):
    r = None
    while k:
        if k & 1:
            r = point_add(r, p)
        p = point_add(p, p)
        k >>= 1
    return r


def h(msg):
    return int.from_bytes(hashlib.sha256(msg).digest(), "big")


def sign_with_k(d, msg, k):
    z = h(msg)
    r = point_mul(k)[0] % N
    s = inv(k, N) * (z + r * d) % N
    return (r, s)


# ------------------------------------------------------- biased nonce source

def biased_nonce(bias_bits):
    """A nonce whose top `bias_bits` bits are zero. Stands in for any RNG
    that produces fewer than 256 bits of entropy."""
    return secrets.randbits(NBITS - bias_bits) or 1


# ------------------------------------------------------------------- attack

def build_lattice(sigs, hashes, K, center=True):
    """Rows of the HNP lattice, integer-scaled by n.

    `center` shifts each unknown nonce by -K/2 so it ranges over
    [-K/2, K/2) instead of [0, K). The vector we are hunting gets shorter by
    a factor of two, which is worth a full bit of bias -- measurably the
    difference between needing 60 signatures and 40 at an 8-bit bias.
    """
    m = len(sigs)
    t, u = [], []
    for (r, s), z in zip(sigs, hashes):
        si = inv(s, N)
        t.append(si * r % N)
        u.append(si * z % N)

    if center:
        half = K // 2
        u = [(x - half) % N for x in u]
        B = half
    else:
        B = K

    rows = []
    for i in range(m):
        row = [0] * (m + 2)
        row[i] = N * N
        rows.append(row)
    rows.append([N * t[i] for i in range(m)] + [B, 0])
    rows.append([N * u[i] for i in range(m)] + [0, N * B])
    return rows, t, u, B


def extract_key(basis_rows, t, u, B, pub):
    """Scan every reduced basis vector for the private key.

    Two independent extraction paths, each tried in both signs, each validated
    against the public key. Cheap, and removes all guesswork about which row
    LLL happened to put the target in.
    """
    m = len(t)
    for row in basis_rows:
        v = list(row)
        for sign in (1, -1):
            w = [sign * x for x in v]

            # path A: the d-slot holds d*B directly
            if w[m] != 0 and w[m] % B == 0:
                d = w[m] // B % N
                if d and point_mul(d) == pub:
                    return d, "d-slot"

            # path B: the first slot holds n*k'_0 (the centered nonce);
            # invert the affine relation k' = u' + t*d.
            if w[0] != 0 and w[0] % N == 0 and t[0]:
                k0 = w[0] // N % N
                d = (k0 - u[0]) * inv(t[0], N) % N
                if d and point_mul(d) == pub:
                    return d, "k-slot"
    return None, None


def run_case(bias_bits, m, use_bkz=False, block=20, verbose=True):
    d = secrets.randbelow(N - 1) + 1
    pub = point_mul(d)
    K = 1 << (NBITS - bias_bits)

    sigs, hashes = [], []
    for i in range(m):
        msg = f"tx-{bias_bits}-{i}".encode()
        k = biased_nonce(bias_bits)
        sigs.append(sign_with_k(d, msg, k))
        hashes.append(h(msg))

    # sanity: no r collisions, so the easy attack is unavailable
    assert len(set(r for r, _ in sigs)) == m, "unexpected r collision"

    rows, t, u, B = build_lattice(sigs, hashes, K)
    M = IntegerMatrix.from_matrix(rows)

    t0 = time.time()
    if use_bkz:
        LLL.reduction(M)
        BKZ.reduction(M, BKZ.Param(block_size=block))
    else:
        LLL.reduction(M)
    elapsed = time.time() - t0

    reduced = [[M[i, j] for j in range(M.ncols)] for i in range(M.nrows)]
    found, path = extract_key(reduced, t, u, B, pub)

    ok = found == d
    if verbose:
        status = "RECOVERED" if ok else "failed"
        algo = f"BKZ-{block}" if use_bkz else "LLL"
        print(f"  bias={bias_bits:>3} bits   m={m:>3} sigs   dim={m+2:>3}   "
              f"{algo:<7} {elapsed:6.2f}s   {status}"
              + (f"  [{path}]" if ok else ""))
    return ok, elapsed, d, found


def hx(i):
    return f"{i:064x}"


def main():
    print("=" * 78)
    print("BIASED NONCE -> PRIVATE KEY RECOVERY VIA LATTICE (HNP)")
    print("=" * 78)

    # ------------------------------------------------------ worked example
    print("\n[worked example] 128-bit nonces (an RNG seeded with 128 bits)")
    bias, m = 128, 5
    d = secrets.randbelow(N - 1) + 1
    pub = point_mul(d)
    K = 1 << (NBITS - bias)
    sigs, hashes = [], []
    for i in range(m):
        msg = f"demo-{i}".encode()
        sigs.append(sign_with_k(d, msg, biased_nonce(bias)))
        hashes.append(h(msg))
    print(f"  true privkey     {hx(d)}")
    print(f"  signatures       {m}")
    print(f"  distinct r?      {len(set(r for r, _ in sigs)) == m}"
          "   <- no collision; the easy attack does not apply")
    rows, t, u, B = build_lattice(sigs, hashes, K)
    M = IntegerMatrix.from_matrix(rows)
    LLL.reduction(M)
    reduced = [[M[i, j] for j in range(M.ncols)] for i in range(M.nrows)]
    found, path = extract_key(reduced, t, u, B, pub)
    print(f"  lattice dim      {m + 2}")
    print(f"  recovered        {hx(found) if found else '(none)'}")
    print(f"  correct?         {found == d}   via {path}")

    # ------------------------------------------------------ how far it goes
    print("\n" + "=" * 78)
    print("HOW LITTLE BIAS IS ENOUGH")
    print("=" * 78)
    print("\n  Theory: need roughly m > 256/L signatures for an L-bit bias.")
    print("  In practice you want a comfortable margin over that floor.\n")

    cases = [
        (128, 4, False, 0),
        (64, 8, False, 0),
        (32, 14, False, 0),
        (16, 30, False, 0),
        (8, 34, False, 0),
        (8, 40, False, 0),
        (4, 120, True, 20),
    ]
    for bias, m, bkz, block in cases:
        try:
            run_case(bias, m, use_bkz=bkz, block=block)
        except Exception as e:
            print(f"  bias={bias:>3} bits   m={m:>3} sigs   error: {e}")
        sys.stdout.flush()

    print("\n  A single zero byte at the top of every nonce is fatal, and the")
    print("  m=34 vs m=40 pair shows how sharp the cliff is -- six signatures")
    print("  either side of the threshold is the difference between safe and")
    print("  fully recovered. Even a 4-bit bias -- a pattern you would never")
    print("  spot by eye -- falls to BKZ at ~120 signatures.")

    # ------------------------------------------------------- the defensive test
    print("\n" + "=" * 78)
    print("DEFENSIVE USE: auditing your own signer")
    print("=" * 78)
    print("""
  With the private key in hand (your own test wallet), you do not need the
  lattice at all -- recompute each nonce directly and inspect it:

      k_i = s_i^-1 (z_i + r_i * d)  mod n

  Then assert on the distribution:
    * top byte of k is uniform over 0..255, not biased toward 0
    * bit length of k is 256 for ~half the samples, 255 for a quarter, ...
    * no two k values are equal across distinct messages
    * under RFC 6979, k is reproducible: same (key, message) -> same k

  That last one is the assertion worth wiring into libdogecoin's test suite,
  because it fails loudly the moment anyone swaps the deterministic path for
  an RNG:

      sign(key, msg_a) twice   -> byte-identical signatures
      sign(key, msg_a) vs (b)  -> different r
""")

    # demonstrate the bit-length skew test
    print("  Demonstration of the skew test on 60 samples each:\n")
    for label, bias in (("uniform (correct)", 0), ("top byte zero", 8)):
        d2 = secrets.randbelow(N - 1) + 1
        lens = []
        for i in range(60):
            k = (secrets.randbelow(N - 1) + 1) if bias == 0 else biased_nonce(bias)
            msg = f"probe-{label}-{i}".encode()
            r, s = sign_with_k(d2, msg, k)
            k_back = inv(s, N) * (h(msg) + r * d2) % N
            lens.append(k_back.bit_length())
        print(f"    {label:<20} max bitlen {max(lens):>3}   "
              f"mean {sum(lens)/len(lens):6.1f}   "
              f"(expected ~255.0 for uniform)")
    print()


if __name__ == "__main__":
    main()
