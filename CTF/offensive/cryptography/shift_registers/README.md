# Shift Registers

> **Description**: I learned about lfsr today in school so i decided to implement it in my program>

## Overview

| Property | Detail |
| --- | --- |
| CTF | CyLab |
| Category | Cryptography |
| Difficulty | Medium |
| Files | [chall.py](https://challenge-files.cylabacademy.net/library/d252af24c7e168d84bf90bbeeceb0c43186cee51e7a92545e0f3ad799c3eedaf/chall.py) [output.txt](https://challenge-files.cylabacademy.net/library/d252af24c7e168d84bf90bbeeceb0c43186cee51e7a92545e0f3ad799c3eedaf/output.txt) |
| Flag format | academy{...} |

## Given Files

`chall.py`

```python
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Random import get_random_bytes

key = bytes_to_long(get_random_bytes(126))

def steplfsr(lfsr):
    b7 = (lfsr >> 7) & 1
    b5 = (lfsr >> 5) & 1
    b4 = (lfsr >> 4) & 1
    b3 = (lfsr >> 3) & 1

    feedback = b7 ^ b5 ^ b4 ^ b3
    lfsr = (feedback << 7) | (lfsr >> 1)
    return lfsr 

def encrypt_lfsr(pt_bytes):
    output = bytearray()
    lfsr = key & 0xFF
    for p in pt_bytes:
        lfsr = steplfsr(lfsr)
        ks = lfsr
        output.append(p ^ ks)
    return bytes_to_long(bytes(output))

pt = b"[redacted]"
ct = encrypt_lfsr(pt)

print(long_to_bytes(ct).hex())
```

`output.txt`

```text
30cbb50e507774fdafd01e0bfdbc38d5eadf92991cdd347064e37444e517d661cea9
```

## Analysis
The script is a **stream cipher** built on an **LFSR** (Linear Feedback Shift Register).

### What is LFSR?
A shift register whose input bit is a linear function of its previous state.

## Vulnerability
The key looks huge: `get_random_bytes(126) is **1008 bits**. But the cipher only ever uses:

```python
lfsr = key & 0xFF
```

`& 0xFF` keeps only the lowest 8 bits, so the real key is a single byte. There are only

$$
2^8 = 256
$$

possible starting states, which is tiny enough to try every one in under a second.

There is a second weakness too: because the keystream byte *is* the LFSR state, recovering **one** keystream byte tells the entire internal state.

## Solve Script

```python
# solve.py
ct = bytes.fromhex(
    "30cbb50e507774fdafd01e0bfdbc38d5eadf92991cdd347064e37444e517d661cea9"
)

def step(s):
    f = ((s >> 7) ^ (s >> 5) ^ (s >> 4) ^ (s >> 3)) & 1
    return (f << 7) | (s >> 1)

# Brute-force all 256 seeds
for seed in range(256):
    s, out = seed, bytearray()
    for c in ct:
        s = step(s)
        out.append(c ^ s)
    if out.startswith(b"academy{"):
        print(seed, out.decode())
```

## Flag

<details>
<summary>Spoiler</summary>

`academy{l1n3ar_f33dback_sh1ft_r3g}`

</details>

## Lessons Learned

- A big random key doesn't help if the code throws most of it away. Always check how much of the key is **actually used** (`& 0xFF` = 8 bits).
- Know flag formats (`academy{`) are a free *known-plaintext* foothold in CyLab.

## References

- [LFSR (Wikipedia)](https://en.wikipedia.org/wiki/Linear-feedback_shift_register)
