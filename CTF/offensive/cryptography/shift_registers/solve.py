ct = bytes.fromhex(
    "30cbb50e507774fdafd01e0bfdbc38d5eadf92991cdd347064e37444e517d661cea9"
)

def step(s):
    f = ((s >> 7) ^ (s >> 5) ^ (s >> 4) ^ (s >> 3)) & 1
    return (f << 7) | (s >> 1)

for seed in range(256):
    s, out = seed, bytearray()
    for c in ct:
        s = step(s)
        out.append(c ^ s)
    if out.startswith(b"academy{"):
        print(seed, out.decode())