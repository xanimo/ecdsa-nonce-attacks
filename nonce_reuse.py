#!/usr/bin/env python3
"""
ECDSA nonce reuse -> private key recovery, on secp256k1.

Pure stdlib. No deps. All keys are generated locally by this script.

The math
--------
An ECDSA signature over message hash z with private key d and nonce k is

    r = (k*G).x  mod n
    s = k^-1 * (z + r*d)  mod n

Sign two different messages with the SAME k and you get the same r, plus

    s1 = k^-1 (z1 + r d)
    s2 = k^-1 (z2 + r d)

Subtract:

    s1 - s2 = k^-1 (z1 - z2)
    =>  k = (z1 - z2) * (s1 - s2)^-1   mod n

k is now known, so back-substitute into either signature:

    s1 * k = z1 + r d
    =>  d = (s1*k - z1) * r^-1   mod n

Two signatures. Two modular inversions. No search, no lattice, no luck.
The equal r value is the tell -- it is visible on-chain to anyone.
"""

import hashlib
import hmac
import secrets

# ---------------------------------------------------------------- secp256k1

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A = 0
B = 7
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)


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
        lam = (3 * x1 * x1 + A) * inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * inv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def point_mul(k, p=G):
    r = None
    while k:
        if k & 1:
            r = point_add(r, p)
        p = point_add(p, p)
        k >>= 1
    return r


# ---------------------------------------------------------------- ECDSA

def h(msg: bytes) -> int:
    return int.from_bytes(hashlib.sha256(msg).digest(), "big")


def sign(d: int, msg: bytes, k: int):
    """Sign with a CALLER-SUPPLIED nonce. This is the footgun, made explicit."""
    z = h(msg)
    r = point_mul(k)[0] % N
    s = inv(k, N) * (z + r * d) % N
    if r == 0 or s == 0:
        raise ValueError("degenerate signature, pick another k")
    return (r, s)


def verify(pub, msg: bytes, sig):
    r, s = sig
    if not (1 <= r < N and 1 <= s < N):
        return False
    z = h(msg)
    w = inv(s, N)
    pt = point_add(point_mul(z * w % N, G), point_mul(r * w % N, pub))
    return pt is not None and pt[0] % N == r


# ---------------------------------------------------------------- the attack

def recover_nonce(z1, s1, z2, s2):
    """k = (z1 - z2) / (s1 - s2) mod n"""
    return (z1 - z2) * inv((s1 - s2) % N, N) % N


def recover_privkey(r, s1, z1, k):
    """d = (s1*k - z1) / r mod n"""
    return (s1 * k - z1) * inv(r, N) % N


def attack(msg1, sig1, msg2, sig2):
    r1, s1 = sig1
    r2, s2 = sig2
    assert r1 == r2, "different r -- nonces were not reused"
    r = r1
    z1, z2 = h(msg1), h(msg2)

    # s1 - s2 == 0 would mean z1 == z2, i.e. the same message: no information.
    if (s1 - s2) % N == 0:
        raise ValueError("s1 == s2; identical messages leak nothing")

    # Sign flip ambiguity: some stacks emit low-s normalized signatures, which
    # can negate s. Try both and keep whichever reproduces a consistent key.
    for sa, sb in ((s1, s2), (s1, (-s2) % N)):
        k = recover_nonce(z1, sa, z2, sb)
        d = recover_privkey(r, sa, z1, k)
        if point_mul(k)[0] % N == r:
            return k, d
    raise ValueError("recovery failed")


def scan_for_reuse(signatures):
    """What you'd actually run over a corpus: bucket by r, flag collisions.

    signatures: list of (label, msg, (r, s))
    """
    seen = {}
    hits = []
    for label, msg, (r, s) in signatures:
        if r in seen:
            hits.append((seen[r], (label, msg, (r, s))))
        else:
            seen[r] = (label, msg, (r, s))
    return hits


# ---------------------------------------------------------------- RFC 6979

def rfc6979_k(d: int, msg: bytes) -> int:
    """Deterministic nonce. k = f(privkey, message), never from an RNG.

    This is what libsecp256k1 / libdogecoin actually do, and it is why the
    attack above does not apply to them: two different messages cannot
    produce the same k, because k is a hash of the message.
    """
    z = h(msg)
    x = d.to_bytes(32, "big")
    zb = (z % N).to_bytes(32, "big")
    v = b"\x01" * 32
    kk = b"\x00" * 32
    kk = hmac.new(kk, v + b"\x00" + x + zb, hashlib.sha256).digest()
    v = hmac.new(kk, v, hashlib.sha256).digest()
    kk = hmac.new(kk, v + b"\x01" + x + zb, hashlib.sha256).digest()
    v = hmac.new(kk, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(kk, v, hashlib.sha256).digest()
        cand = int.from_bytes(v, "big")
        if 1 <= cand < N:
            return cand
        kk = hmac.new(kk, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(kk, v, hashlib.sha256).digest()


# ---------------------------------------------------------------- demo

def hx(i):
    return f"{i:064x}"


def main():
    print("=" * 72)
    print("ECDSA NONCE REUSE -> PRIVATE KEY RECOVERY  (secp256k1)")
    print("=" * 72)

    d = secrets.randbelow(N - 1) + 1
    pub = point_mul(d)
    print("\n[setup] freshly generated keypair, local to this process")
    print(f"  privkey d   {hx(d)}")
    print(f"  pubkey  x   {hx(pub[0])}")

    m1 = b"spend 1 DOGE to alice"
    m2 = b"spend 42 DOGE to bob"

    # THE BUG: one k, two messages.
    k = secrets.randbelow(N - 1) + 1
    sig1 = sign(d, m1, k)
    sig2 = sign(d, m2, k)

    print("\n[victim] signs two different messages, reusing one nonce")
    print(f"  msg1        {m1.decode()}")
    print(f"  msg2        {m2.decode()}")
    print(f"  true k      {hx(k)}    <- attacker does NOT see this")
    print(f"  sig1 r      {hx(sig1[0])}")
    print(f"  sig1 s      {hx(sig1[1])}")
    print(f"  sig2 r      {hx(sig2[0])}    <- identical. the tell.")
    print(f"  sig2 s      {hx(sig2[1])}")
    print(f"  both verify {verify(pub, m1, sig1) and verify(pub, m2, sig2)}")

    print("\n[attacker] sees only: msg1, msg2, sig1, sig2, pubkey")
    k_rec, d_rec = attack(m1, sig1, m2, sig2)
    print(f"  nonce k     {hx(k_rec)}")
    print(f"  privkey d   {hx(d_rec)}")

    print("\n[result]")
    print(f"  nonce match     {k_rec == k}")
    print(f"  privkey match   {d_rec == d}")
    print(f"  pubkey re-derives {point_mul(d_rec) == pub}")

    # ------------------------------------------------------------ scanning
    print("\n" + "=" * 72)
    print("DETECTION: what an audit actually runs")
    print("=" * 72)
    corpus = []
    d2 = secrets.randbelow(N - 1) + 1
    for i in range(6):
        msg = f"clean tx #{i}".encode()
        corpus.append((f"tx{i}", msg, sign(d2, msg, rfc6979_k(d2, msg))))
    corpus.append(("bad_a", m1, sig1))
    corpus.append(("bad_b", m2, sig2))

    hits = scan_for_reuse(corpus)
    print(f"\n  scanned {len(corpus)} signatures")
    print(f"  r-value collisions: {len(hits)}")
    for (la, ma, sa), (lb, mb, sb) in hits:
        print(f"    {la} <-> {lb}   shared r = {hx(sa[0])[:32]}...")
        _, leaked = attack(ma, sa, mb, sb)
        print(f"      -> key recovered: {hx(leaked)}")

    # ------------------------------------------------------------ the fix
    print("\n" + "=" * 72)
    print("WHY RFC 6979 KILLS THIS")
    print("=" * 72)
    d3 = secrets.randbelow(N - 1) + 1
    ka = rfc6979_k(d3, m1)
    kb = rfc6979_k(d3, m2)
    ka_again = rfc6979_k(d3, m1)
    sa = sign(d3, m1, ka)
    sb = sign(d3, m2, kb)
    print(f"\n  k(msg1)         {hx(ka)}")
    print(f"  k(msg2)         {hx(kb)}")
    print(f"  different?      {ka != kb}   <- k is a function of the message")
    print(f"  k(msg1) again   {hx(ka_again)}")
    print(f"  reproducible?   {ka == ka_again}")
    print(f"  r values differ {sa[0] != sb[0]}   <- no collision, nothing to subtract")
    print("\n  Deterministic k removes the RNG from the signing path entirely.")
    print("  No entropy failure, no VM fork, no repeated /dev/urandom read")
    print("  can cause reuse across distinct messages.")
    print()


if __name__ == "__main__":
    main()
