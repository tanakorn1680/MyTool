"""
LuaR Obfuscator v2
รับ Lua bytecode (หรือ source) → output Lua script ที่รันบน GG ได้
แต่อ่าน/แกะยากมาก

Layers:
  1. Rolling XOR (256-byte key derived from random seed)
  2. Chunk reorder (chunks สับตำแหน่ง, decode ตอน run ด้วย index table)
  3. Seed split (seed 4 bytes กระจายใน dead code ไม่อยู่ติดกัน)
  4. Variable name mangling (ชื่อตัวแปรสุ่ม hex-like)
  5. Dead code injection (ตัวแปรปลอม, math ไม่มีผล)
  6. String split (hex data แบ่งเป็น chunks สั้นๆ สุ่มขนาด)
"""

import os, random, struct, hashlib

# ── Name pool ──────────────────────────────────────────────────────────────
def _mangle(seed_int):
    rng = random.Random(seed_int)
    used = set()
    def name():
        while True:
            n = "_" + "".join(rng.choice("0123456789abcdef") for _ in range(6))
            if n not in used:
                used.add(n)
                return n
    return name

# ── Rolling XOR ──────────────────────────────────────────────────────────────
def _make_key(seed: int) -> bytes:
    """256-byte key from seed via SHA-256 chain."""
    h = hashlib.sha256(struct.pack(">I", seed)).digest()
    key = h
    while len(key) < 256:
        h = hashlib.sha256(h).digest()
        key += h
    return key[:256]

def _xor(data: bytes, key: bytes) -> bytes:
    return bytes(data[i] ^ key[i % 256] for i in range(len(data)))

# ── Chunk + reorder ──────────────────────────────────────────────────────────
def _chunk_and_shuffle(hex_str: str, rng: random.Random):
    """Split hex string into variable-size chunks, shuffle, return (chunks, order)."""
    i, chunks = 0, []
    while i < len(hex_str):
        size = rng.randint(200, 600) * 2  # 100-300 bytes per chunk (hex chars)
        size = min(size, len(hex_str) - i)
        # ensure even number of chars
        if size % 2: size += 1
        if size == 0: break
        chunks.append(hex_str[i:i+size])
        i += size

    order = list(range(len(chunks)))
    rng.shuffle(order)
    shuffled = [chunks[order[i]] for i in range(len(chunks))]
    # inverse permutation: where does each shuffled slot go?
    inv = [0] * len(order)
    for i, o in enumerate(order):
        inv[o] = i
    return shuffled, inv

# ── Dead code ──────────────────────────────────────────────────────────────
def _dead_lines(rng: random.Random, names, count=8):
    ops = [
        lambda: f"local {names()} = {rng.randint(1,9999)} * {rng.randint(1,9999)}",
        lambda: f"local {names()} = ({rng.randint(1,255)} ~ {rng.randint(1,255)})",
        lambda: f"local {names()} = string.len(\"{_rand_str(rng, 6)}\")",
        lambda: f"local {names()} = math.floor({rng.uniform(1,999):.4f})",
        lambda: f"-- {_rand_str(rng, 12)}",
    ]
    return [rng.choice(ops)() for _ in range(count)]

def _rand_str(rng, n):
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))

# ── Seed split: hide 4-byte seed across 4 dead variables ──────────────────
def _seed_vars(seed: int, rng: random.Random, names):
    """Return (lines_to_insert, reconstruct_expr)."""
    b = struct.pack(">I", seed)
    vnames = [names() for _ in range(4)]
    lines = [f"local {vnames[i]} = {b[i]}" for i in range(4)]
    # reconstruct: (v0<<24)|(v1<<16)|(v2<<8)|v3
    expr = (f"({vnames[0]}*16777216)"
            f"+({vnames[1]}*65536)"
            f"+({vnames[2]}*256)"
            f"+{vnames[3]}")
    return lines, expr, vnames

# ── Main obfuscate ──────────────────────────────────────────────────────────
def obfuscate_bytecode(bytecode: bytes) -> bytes:
    """
    Input:  raw Lua bytecode (or any binary to protect)
    Output: Lua source (.lua) that decodes + loads itself at runtime
    """
    seed = struct.unpack(">I", os.urandom(4))[0]
    rng  = random.Random(seed)
    N    = _mangle(rng.randint(0, 0xFFFFFFFF))

    key     = _make_key(seed)
    xored   = _xor(bytecode, key)
    hex_str = xored.hex()

    chunks, inv_order = _chunk_and_shuffle(hex_str, rng)
    n_chunks = len(chunks)

    seed_lines, seed_expr, _ = _seed_vars(seed, rng, N)

    # Variable names for runtime
    v_chunks  = N()   # table holding shuffled chunks
    v_inv     = N()   # inverse order table
    v_key     = N()   # key bytes table
    v_buf     = N()   # reassembly buffer
    v_hex     = N()   # final hex string
    v_xored   = N()   # xored bytes table
    v_out     = N()   # output bytes table
    v_i       = N()   # loop var
    v_b       = N()   # byte var
    v_k       = N()   # key var
    v_fn      = N()   # loaded function
    v_seed    = N()   # reconstructed seed
    v_h       = N()   # hash chain var
    v_t       = N()   # temp table for key
    v_s       = N()   # sha256 helper result
    v_c       = N()   # char var

    # Build chunk assignments
    chunk_lines = []
    for idx, chunk in enumerate(chunks):
        # split each chunk into 2-4 sub-pieces for extra obfuscation
        sub_pieces = []
        ci = 0
        while ci < len(chunk):
            sub_len = rng.randint(80, 200)
            sub_len = min(sub_len, len(chunk) - ci)
            if sub_len % 2: sub_len = max(2, sub_len - 1)
            sub_pieces.append('"' + chunk[ci:ci+sub_len] + '"')
            ci += sub_len
        chunk_lines.append(f"{v_chunks}[{idx+1}] = " + "..".join(sub_pieces))

    # Build inverse order table
    inv_parts = ",".join(str(x+1) for x in inv_order)

    # Dead code scattered
    dead1 = _dead_lines(rng, N, 6)
    dead2 = _dead_lines(rng, N, 5)
    dead3 = _dead_lines(rng, N, 4)

    # ── SHA-256 in pure Lua for key derivation ──────────────────────────────
    # Too complex to embed — use simpler key: derive from seed via linear congruential
    # Key = [((seed * i * 0x5851f42d + 0xc4ceb9fe) >> 8) & 0xFF for i in 1..256]
    # This is fast in Lua and hard to reverse without knowing the constants
    A = 0x5851f42d
    B = 0xc4ceb9fe

    lines = []

    # Header comment (decoy)
    lines += [
        f"-- v{rng.randint(1,9)}.{rng.randint(0,99)}.{rng.randint(0,999)}",
        f"-- build {rng.randint(10000,99999)}",
    ]

    # Seed split
    lines += dead1[:2]
    lines += seed_lines
    lines += dead1[2:]

    # Reconstruct seed
    lines.append(f"local {v_seed} = {seed_expr}")

    # Build key table from seed
    lines += dead2[:2]
    lines += [
        f"local {v_t} = {{}}",
        f"local {v_k} = {v_seed}",
        f"for {v_i}=1,256 do",
        f"  {v_k} = ({v_k} * {A} + {B}) & 0xffffffff",
        f"  {v_t}[{v_i}] = ({v_k} >> 8) & 0xff",
        f"end",
    ]
    lines += dead2[2:]

    # Chunk table
    lines.append(f"local {v_chunks} = {{}}")
    lines += chunk_lines

    # Inverse order
    lines.append(f"local {v_inv} = {{{inv_parts}}}")

    # Reassemble in correct order
    lines += dead3
    lines += [
        f"local {v_buf} = {{}}",
        f"for {v_i}=1,{n_chunks} do",
        f"  {v_buf}[{v_inv}[{v_i}]] = {v_chunks}[{v_i}]",
        f"end",
        f"local {v_hex} = table.concat({v_buf})",
    ]

    # Decode hex + XOR
    lines += [
        f"local {v_out} = {{}}",
        f"for {v_i}=1,#{v_hex},2 do",
        f"  local {v_b} = tonumber({v_hex}:sub({v_i},{v_i}+1),16)",
        f"  {v_out}[#{v_out}+1] = string.char({v_b} ~ {v_t}[({v_i}//2)%256+1])",
        f"end",
        f"local {v_fn} = load(table.concat({v_out}))",
        f"if {v_fn} then {v_fn}() end",
    ]

    return "\n".join(lines).encode("utf-8")
