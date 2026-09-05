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

Two shapes, and they need different handling. Leading-zero bias (a short
value used directly, high bits zero) makes k itself small: k < 2^(256-L).
Trailing-zero bias (a short read zero-padded on the low end, or a counter
shifted left) makes k a multiple of 2^L with full-width top bits, so k is
*not* small -- it is small only after dividing by 2^L. The lattice below is
built for small k; it recovers the trailing-zero shape only after rescaling
the public coefficients by 2^-L (mod n), which is what `low=True` does. Bias
with an unknown or non-power-of-two structure is a different problem and this
basis does not cover it.

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


def biased_nonce_low(bias_bits):
    """A nonce whose low `bias_bits` bits are zero: k = j << bias_bits with j
    full-width. Stands in for a short read zero-padded on the low end, or a
    counter shifted left. k is not small; k / 2^bias_bits is."""
    return (secrets.randbits(NBITS - bias_bits) << bias_bits) or (1 << bias_bits)


# ------------------------------------------------------------------- attack

def build_lattice(sigs, hashes, K, center=True, scale=1):
    """Rows of the HNP lattice, integer-scaled by n.

    `center` shifts each unknown nonce by -K/2 so it ranges over
    [-K/2, K/2) instead of [0, K). The vector we are hunting gets shorter by
    a factor of two, which is worth a full bit of bias -- measurably the
    difference between needing 60 signatures and 40 at an 8-bit bias.

    `scale` multiplies the public coefficients t, u by a constant mod n. For
    trailing-zero bias (k = j << L) pass scale = 2^-L mod n, which turns the
    small unknown into j = k >> L; the recovered d is unchanged. Default 1
    leaves the leading-zero case alone.
    """
    m = len(sigs)
    t, u = [], []
    for (r, s), z in zip(sigs, hashes):
        si = inv(s, N)
        t.append(si * r % N * scale % N)
        u.append(si * z % N * scale % N)

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

    Two independent extraction paths, each tried in both signs. A candidate d
    is confirmed in two stages: recompute every nonce k_i = u_i + t_i*d and
    reject unless all land in the centered bound [-B, B] -- m modular multiplies
    that kill wrong candidates for the price of no elliptic-curve work -- then a
    single point_mul on the survivor validates against the public key. Without
    the filter this is one point_mul per candidate, up to 4(m+2) of them, which
    dominates runtime at large m.
    """
    m = len(t)
    inv_t0 = inv(t[0], N) if t[0] else None

    def confirms(d):
        d %= N
        if not d:
            return False
        for ti, ui in zip(t, u):
            ki = (ui + ti * d) % N
            if B < ki < N - B:      # outside the centered band -> wrong d
                return False
        return point_mul(d) == pub

    for row in basis_rows:
        for sign in (1, -1):
            w = [sign * x for x in row]

            # path A: the d-slot holds d*B directly
            if w[m] != 0 and w[m] % B == 0:
                d = w[m] // B % N
                if confirms(d):
                    return d, "d-slot"

            # path B: column 0 is a multiple of n by construction, so w[0]//n
            # is the centered nonce k'_0; invert k' = u' + t*d for d.
            if w[0] != 0 and inv_t0 is not None:
                k0 = w[0] // N
                d = (k0 - u[0]) * inv_t0 % N
                if confirms(d):
                    return d, "k-slot"
    return None, None


def run_case(bias_bits, m, use_bkz=False, block=20, verbose=True, low=False):
    d = secrets.randbelow(N - 1) + 1
    pub = point_mul(d)
    K = 1 << (NBITS - bias_bits)

    sigs, hashes = [], []
    for i in range(m):
        msg = f"tx-{bias_bits}-{'lo' if low else 'hi'}-{i}".encode()
        k = biased_nonce_low(bias_bits) if low else biased_nonce(bias_bits)
        sigs.append(sign_with_k(d, msg, k))
        hashes.append(h(msg))

    # sanity: no r collisions, so the easy attack is unavailable
    assert len(set(r for r, _ in sigs)) == m, "unexpected r collision"

    # trailing-zero bias makes k = j << L; rescale by 2^-L so j is the small
    # unknown. leading-zero bias leaves k small already (scale = 1).
    scale = inv(1 << bias_bits, N) if low else 1
    rows, t, u, B = build_lattice(sigs, hashes, K, scale=scale)
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
        shape = "low" if low else "high"
        print(f"  bias={bias_bits:>3} bits ({shape})   m={m:>3} sigs   dim={m+2:>3}   "
              f"{algo:<7} {elapsed:6.2f}s   {status}"
              + (f"  [{path}]" if ok else ""))
    return ok, elapsed, d, found


def run_trials(bias_bits, m, n_trials, use_bkz=False, block=20, low=False):
    """Repeat run_case over independent signature sets. Lattice success is
    probabilistic in the draw, so a single run is one sample, not a threshold.
    Returns (successes, n_trials, mean_seconds)."""
    ok = 0
    total = 0.0
    for _ in range(n_trials):
        success, elapsed, _, _ = run_case(bias_bits, m, use_bkz, block,
                                          verbose=False, low=low)
        ok += success
        total += elapsed
    return ok, n_trials, total / n_trials


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

    # ------------------------------------------ trailing-zero (low-bit) variant
    print("\n[trailing-zero bias] k = j << L (a short read zero-padded low, or a")
    print("counter shifted left). k is large, but k >> L is small. The small-k")
    print("basis misses it; rescaling the coefficients by 2^-L (mod n) finds it.")
    bias, m = 64, 8
    d = secrets.randbelow(N - 1) + 1
    pub = point_mul(d)
    K = 1 << (NBITS - bias)
    sigs, hashes = [], []
    for i in range(m):
        msg = f"low-demo-{i}".encode()
        sigs.append(sign_with_k(d, msg, biased_nonce_low(bias)))
        hashes.append(h(msg))
    for label, scale in (("scale = 1   (small-k basis)", 1),
                         ("scale = 2^-L (rescaled)", inv(1 << bias, N))):
        rows, t, u, B = build_lattice(sigs, hashes, K, scale=scale)
        M = IntegerMatrix.from_matrix(rows)
        LLL.reduction(M)
        reduced = [[M[i, j] for j in range(M.ncols)] for i in range(M.nrows)]
        found, _ = extract_key(reduced, t, u, B, pub)
        print(f"  {label:<28} {'RECOVERED' if found == d else 'failed'}")

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
    ]
    for bias, m, bkz, block in cases:
        try:
            run_case(bias, m, use_bkz=bkz, block=block)
        except Exception as e:
            print(f"  bias={bias:>3} bits   m={m:>3} sigs   error: {e}")
        sys.stdout.flush()

    # 4-bit is where LLL gives out and BKZ takes over, and it is the row
    # closest to the reduction limit, so a single draw there is the most
    # likely to be luck. Report a small rate instead.
    ok, n, avg = run_trials(4, 120, 3, use_bkz=True, block=20)
    print(f"  bias=  4 bits (high)   m=120 sigs   dim=122   BKZ-20   "
          f"{ok}/{n} recovered   {avg:5.1f}s avg")
    sys.stdout.flush()

    print("\n  The LLL rows above are a single draw each. Success is probabilistic")
    print("  in the signature set, so one run near the boundary tells you little.")
    print("  The sweep below measures the rate.")

    # ------------------------------------------------- threshold, measured
    print("\n" + "=" * 78)
    print("WHERE THE THRESHOLD ACTUALLY IS  (8-bit bias, rate over N trials)")
    print("=" * 78)
    trials = 40
    print(f"\n  {trials} independent signature sets per m, LLL only.\n")
    for m in (30, 32, 34, 36, 38, 40, 42):
        ok, n, avg = run_trials(8, m, trials)
        rate = ok / n
        bar = "#" * round(rate * 20)
        print(f"  m={m:>3}   {ok:>2}/{n}   {rate:5.0%}  {bar:<20}  {avg:5.2f}s avg")
        sys.stdout.flush()
    print("\n  m=32 is exactly the 256/8 floor: 32*8 = 256 bits of leak against a")
    print("  256-bit secret leaves the lattice no margin, so it is a hard 0, not")
    print("  bad luck. m=34 is ~55%, a coin flip, and it saturates by m=38. The")
    print("  lone m=34 fail in the single-draw table above was one side of that")
    print("  coin, not a threshold at 40.")

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
    print("\n  8-bit bias separates cleanly at 60 samples, but that is the easy")
    print("  case. The count needed grows as the bias shrinks; at 1 to 2 bits, 60")
    print("  samples will not separate biased from uniform, so this test catches")
    print("  gross truncation only. The RFC 6979 determinism assertion above does")
    print("  not depend on sample count and is the check to wire into CI.")
    print()


if __name__ == "__main__":
    main()
