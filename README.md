# ECDSA nonce attacks — working demos

Three self-contained scripts. All keys are generated locally by the scripts
themselves; nothing touches real data.

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

## Measured results

Nonce reuse under low-s, 60 random trials:

```
naive  (z1-z2)/(s1-s2)      30/60   50%
sign-hypothesis search      60/60  100%
```

Biased nonces, lattice recovery (centered HNP basis, secp256k1):

```
bias=128 bits   m=  4 sigs   LLL      0.00s   RECOVERED
bias= 64 bits   m=  8 sigs   LLL      0.00s   RECOVERED
bias= 32 bits   m= 14 sigs   LLL      0.01s   RECOVERED
bias= 16 bits   m= 30 sigs   LLL      0.07s   RECOVERED
bias=  8 bits   m= 34 sigs   LLL      0.09s   failed
bias=  8 bits   m= 40 sigs   LLL      0.15s   RECOVERED
bias=  4 bits   m=120 sigs   BKZ-20  22.04s   RECOVERED
```

No r-collision occurs in any of the lattice cases. Duplicate-r scanning
cannot detect these.

## Reading

- Reuse is loud (duplicate r, greppable). Bias is silent and needs the lattice.
- Centering the unknowns (`k - K/2`) is worth a full bit: 8-bit bias needs
  ~40 signatures centered vs ~60 uncentered.
- The 34-vs-40 pair at 8-bit bias shows how sharp the threshold is.
- RFC 6979 closes both classes at once, because k becomes a function of
  (privkey, message) with no RNG in the path.

## The libdogecoin-facing assertion

```
sign(key, msg_a) twice      -> byte-identical signatures
sign(key, msg_a) vs msg_b   -> different r
recompute k = s^-1(z + r*d) -> bit_length uniform near 256, no repeats
```

That first line fails immediately if anyone ever swaps the deterministic
nonce path for an RNG.
