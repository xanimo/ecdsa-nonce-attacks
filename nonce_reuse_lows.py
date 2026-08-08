#!/usr/bin/env python3
"""
Nonce reuse recovery, hardened against low-s normalization + cross-key cases.

Why this matters on real data
-----------------------------
BIP62 / BIP146 make signers emit "low-s" signatures: after computing s, if
s > n/2 the signer publishes n - s instead. Both forms verify -- that is the
malleability that low-s was introduced to remove.

Consequence for the attack: when you find two signatures sharing an r, you do
NOT know whether each s you are looking at is the raw s or its negation. A
naive  k = (z1-z2)/(s1-s2)  silently produces garbage in roughly half of real
collisions. The fix is to solve under each sign hypothesis and let the public
key adjudicate.

Note that r is UNAFFECTED by the flip -- (kG).x is the same for k and -k --
so detection by duplicate r still works exactly as before. Only the solve
step needs the case split.
"""

import hashlib
import secrets

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)
HALF_N = N >> 1


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


def sign(d, msg, k, low_s=True):
    z = h(msg)
    r = point_mul(k)[0] % N
    s = inv(k, N) * (z + r * d) % N
    flipped = False
    if low_s and s > HALF_N:
        s = N - s
        flipped = True
    return (r, s), flipped


def verify(pub, msg, sig):
    r, s = sig
    if not (1 <= r < N and 1 <= s < N):
        return False
    z = h(msg)
    w = inv(s, N)
    pt = point_add(point_mul(z * w % N, G), point_mul(r * w % N, pub))
    return pt is not None and pt[0] % N == r


# ------------------------------------------------------------------ recovery

def recover(msg1, sig1, msg2, sig2, pub=None):
    """Recover (k, d) from an r-collision, trying every sign hypothesis.

    Returns (k, d, hypothesis) or raises.

    Hypotheses: each published s may be the raw value or its negation mod n.
    That is four combinations, but a global negation of BOTH is a symmetry
    (k -> -k leaves r unchanged and leaves d unchanged), so only two are
    distinct: (+,+) and (+,-).

    If `pub` is supplied it is the authoritative check. Without it we fall
    back to checking that the recovered k actually reproduces r, which is a
    strong but slightly weaker test.
    """
    r1, s1 = sig1
    r2, s2 = sig2
    if r1 != r2:
        raise ValueError("no r-collision: nonces were not reused")
    r = r1
    z1, z2 = h(msg1), h(msg2)

    for label, (sa, sb) in (
        ("(+s1, +s2)", (s1, s2)),
        ("(+s1, -s2)", (s1, (N - s2) % N)),
    ):
        denom = (sa - sb) % N
        if denom == 0:
            continue  # identical messages under this hypothesis: no information
        k = (z1 - z2) * inv(denom, N) % N
        if k == 0:
            continue
        d = (sa * k - z1) * inv(r, N) % N
        if d == 0:
            continue
        if pub is not None:
            if point_mul(d) == pub:
                return k, d, label
        else:
            pt = point_mul(k)
            if pt is not None and pt[0] % N == r:
                return k, d, label
    raise ValueError("recovery failed under all sign hypotheses")


def recover_naive(msg1, sig1, msg2, sig2):
    """The textbook version. Included to show it failing."""
    r, s1 = sig1
    _, s2 = sig2
    z1, z2 = h(msg1), h(msg2)
    k = (z1 - z2) * inv((s1 - s2) % N, N) % N
    return (s1 * k - z1) * inv(r, N) % N


# ------------------------------------------------------------------ demo

def hx(i):
    return f"{i:064x}"


def trial(seed_msgs, low_s=True):
    d = secrets.randbelow(N - 1) + 1
    pub = point_mul(d)
    k = secrets.randbelow(N - 1) + 1
    m1, m2 = seed_msgs
    sig1, f1 = sign(d, m1, k, low_s=low_s)
    sig2, f2 = sign(d, m2, k, low_s=low_s)
    assert verify(pub, m1, sig1) and verify(pub, m2, sig2)
    return d, pub, k, m1, sig1, f1, m2, sig2, f2


def main():
    print("=" * 74)
    print("NONCE REUSE UNDER LOW-S NORMALIZATION")
    print("=" * 74)

    # Hunt for a case where exactly one of the two signatures got flipped.
    # That is the case the naive formula gets wrong; it happens ~50% of the
    # time on real low-s data.
    for attempt in range(200):
        d, pub, k, m1, sig1, f1, m2, sig2, f2 = trial(
            (b"spend 1 DOGE to alice", b"spend 42 DOGE to bob")
        )
        if f1 != f2:
            break
    else:
        raise SystemExit("no mixed-flip case found (very unlikely)")

    print(f"\n[setup] found a mixed-flip collision after {attempt + 1} attempts")
    print(f"  privkey d        {hx(d)}")
    print(f"  shared r         {hx(sig1[0])}")
    print(f"  sig1 s           {hx(sig1[1])}   flipped={f1}")
    print(f"  sig2 s           {hx(sig2[1])}   flipped={f2}")
    print(f"  both verify      {verify(pub, m1, sig1) and verify(pub, m2, sig2)}")

    naive = recover_naive(m1, sig1, m2, sig2)
    print("\n[naive formula]  k = (z1-z2)/(s1-s2), no sign hypothesis")
    print(f"  recovered d      {hx(naive)}")
    print(f"  correct?         {naive == d}")
    print(f"  pubkey matches?  {point_mul(naive) == pub}")

    k_r, d_r, hyp = recover(m1, sig1, m2, sig2, pub=pub)
    print("\n[hypothesis search]")
    print(f"  winning case     {hyp}")
    print(f"  recovered k      {hx(k_r)}")
    print(f"  recovered d      {hx(d_r)}")
    print(f"  correct?         {d_r == d}")
    print(f"  pubkey matches?  {point_mul(d_r) == pub}")
    print(f"  note: recovered k is {'k' if k_r == k else '-k (mod n)'};"
          " both give the same r, and the same d.")

    # ---------------------------------------------------------------- sweep
    print("\n" + "-" * 74)
    print("How often does the naive formula fail on low-s data?")
    print("-" * 74)
    naive_ok = robust_ok = 0
    trials = 60
    for i in range(trials):
        d, pub, k, m1, sig1, f1, m2, sig2, f2 = trial(
            (f"tx-a-{i}".encode(), f"tx-b-{i}".encode())
        )
        if recover_naive(m1, sig1, m2, sig2) == d:
            naive_ok += 1
        try:
            if recover(m1, sig1, m2, sig2, pub=pub)[1] == d:
                robust_ok += 1
        except ValueError:
            pass
    print(f"  naive:  {naive_ok}/{trials} recovered  ({100*naive_ok//trials}%)")
    print(f"  robust: {robust_ok}/{trials} recovered ({100*robust_ok//trials}%)")

    # ----------------------------------------------------------- cross-key
    print("\n" + "=" * 74)
    print("CROSS-KEY NONCE REUSE: two different keys, same k")
    print("=" * 74)
    k_shared = secrets.randbelow(N - 1) + 1
    dA = secrets.randbelow(N - 1) + 1
    dB = secrets.randbelow(N - 1) + 1
    pubA, pubB = point_mul(dA), point_mul(dB)
    mA, mB = b"alice tx", b"bob tx"
    sigA, _ = sign(dA, mA, k_shared)
    sigB, _ = sign(dB, mB, k_shared)

    print(f"\n  key A d          {hx(dA)}")
    print(f"  key B d          {hx(dB)}")
    print(f"  shared r         {hx(sigA[0])}")
    print(f"  r collision?     {sigA[0] == sigB[0]}   <- still detectable")

    print("\n  Two equations, three unknowns (k, dA, dB). Not solvable alone:")
    print("    sA = k^-1 (zA + r dA)")
    print("    sB = k^-1 (zB + r dB)")
    print("  Subtracting no longer cancels the key term.")

    print("\n  But it collapses the moment ONE key is known -- k falls out of")
    print("  that signature, and k unlocks the other key.")
    print("  (Both steps need the same sign hypothesis search as above.)")

    # Step 1: k from key A. sigA's s may be the low-s negation, so try both;
    # the correct k is the one whose point reproduces r.
    k_from_A = None
    for sa in (sigA[1], (N - sigA[1]) % N):
        cand = inv(sa, N) * (h(mA) + sigA[0] * dA) % N
        pt = point_mul(cand)
        if pt is not None and pt[0] % N == sigA[0]:
            k_from_A = cand
            break
    # k and -k are both valid preimages of r; keep whichever we found.
    same_k = k_from_A in (k_shared, (N - k_shared) % N)

    # Step 2: key B from k. Same ambiguity on sigB, plus the +-k ambiguity,
    # so sweep and let pubB adjudicate.
    dB_rec = None
    for sb in (sigB[1], (N - sigB[1]) % N):
        for kk in (k_from_A, (N - k_from_A) % N):
            cand = (sb * kk - h(mB)) * inv(sigB[0], N) % N
            if point_mul(cand) == pubB:
                dB_rec = cand
                break
        if dB_rec is not None:
            break

    print(f"    k from key A   {hx(k_from_A)}   matches shared k (up to sign)={same_k}")
    print(f"    -> key B       {hx(dB_rec)}   correct={dB_rec == dB}")
    print("\n  Practical read: a shared-RNG bug across a fleet of wallets means")
    print("  one compromised key deanonymizes every other key that collided")
    print("  with it. Detection is still just: GROUP BY r HAVING COUNT(*) > 1.")
    print()


if __name__ == "__main__":
    main()
