# ECDSA nonce attacks — working demos

Three self-contained scripts. All keys are generated locally by the scripts
themselves; nothing touches real data. MIT licensed.

Duplicate-r grepping catches the loud class of nonce failure and is blind to
the quiet class by construction. `hnp_bias.py` asserts every signature it uses
has a distinct r, then recovers the key from the bias alone. A scanner that
keys on repeated r never sees it, at any scale.

| file | attack | deps |
|---|---|---|
| `nonce_reuse.py` | exact nonce reuse -> key recovery, + r-collision scanner, + RFC 6979 contrast | stdlib |
| `nonce_reuse_lows.py` | same, hardened for BIP62 low-s normalization; plus cross-key reuse | stdlib |
| `hnp_bias.py` | *biased* nonces -> key recovery by lattice reduction (Hidden Number Problem) | `fpylll`, `cysignals` |

```
python3 nonce_reuse.py
python3 nonce_reuse_lows.py
pip install fpylll cysignals && python3 hnp_bias.py   # last case takes ~25s
```

## Low-s breaks the naive reuse formula half the time

Nonce reuse under low-s, 60 random trials:

```
naive  (z1-z2)/(s1-s2)      30/60   50%
sign-hypothesis search      60/60  100%
```

BIP62 low-s normalization negates s when s > n/2, so two signatures sharing a
nonce can disagree on sign convention. The naive `(z1-z2)/(s1-s2)` fails exactly
when one of the pair got flipped and the other did not, which is 2*(1/2)*(1/2)
= 1/2 by construction. Both-flipped and neither-flipped still recover. The 60
trials confirm the rate, they do not discover it.

Most public nonce-reuse scanners use the naive form. On any chain with low-s
policy (bitcoin since 2016, dogecoin since the backport) that halves their
detection rate on duplicate-r reuse.

## Biased nonces, lattice recovery

centered HNP basis, secp256k1:

```
bias=128 bits   m=  4 sigs   LLL      0.00s   RECOVERED
bias= 64 bits   m=  8 sigs   LLL      0.00s   RECOVERED
bias= 32 bits   m= 14 sigs   LLL      0.01s   RECOVERED
bias= 16 bits   m= 30 sigs   LLL      0.07s   RECOVERED
bias=  8 bits   m= 34 sigs   LLL      0.09s   failed
bias=  8 bits   m= 40 sigs   LLL      0.15s   RECOVERED
bias=  4 bits   m=120 sigs   BKZ-20  22.04s   RECOVERED
```

Each row above is a single draw, and lattice success is probabilistic in the
signature set. Run 40 independent sets per m at 8-bit bias and the threshold is
a band, not a cliff:

```
m=30    0/40     0%
m=32    0/40     0%      <- the 256/8 theory floor; never solves
m=34   22/40    55%      <- a coin flip
m=36   36/40    90%
m=38   40/40   100%
m=40   40/40   100%
```

The lone m=34 failure in the single-draw table is one side of that 55% coin,
not evidence of a threshold at 40. `run_trials()` in `hnp_bias.py` produces the
sweep.

## Reading

- Roughly m > 256/bias signatures, plus a few rows of overhead. LLL runs out
  near 4-bit bias and BKZ takes over.
- Centering the unknowns (`k - K/2`) is worth a full bit: 8-bit bias needs ~40
  signatures centered vs ~60 uncentered.
- RFC 6979 closes both classes at once, because k becomes a function of
  (privkey, message) with no RNG in the path.

## The libdogecoin-facing assertion

```
sign(key, msg_a) twice      -> byte-identical signatures
sign(key, msg_a) vs msg_b   -> different r
recompute k = s^-1(z + r*d) -> feed to the lattice attack; it must NOT recover d
```

The first line fails immediately if anyone ever swaps the deterministic nonce
path for an RNG, and it is cheap enough to run in CI.

The third line is a positive test, not a clean bill. Feeding recomputed k to
the lattice recovers d only for HNP-style bias with a known bound (fixed count
of zero high or low bits). A recovery proves the source is biased; a failure
does not prove it is clean, since correlated-but-full-entropy nonces or bias
with an unknown bound slip past the lattice. Prefer it over a `bit_length`
histogram, which catches truncation and gross skew but not modulo-reduction
structure.

One signing entry point is not path coverage. PSBT and the python bindings are
where a divergent nonce source would most plausibly hide, so each path needs
its own determinism check.

## Disclosure

The r-collision scanner is written against locally generated keys. If it is
ever pointed at a live chain and hits, there is a real private key at the end
of it, which is a disclosure situation and not a writeup. Treat it that way.
