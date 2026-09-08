"""
LuaR Obfuscator v3 — ULTRA MODE
Input:  raw bytes (Lua source หรือ bytecode ก็ได้)
Output: Lua source ที่รันบน GG ได้ แต่อ่าน/แกะแทบเป็นไปไม่ได้

Pipeline encoding:
  1. Fibonacci-Diffusion XOR  — key stateful, ขึ้นอยู่กับ ciphertext ก่อนหน้า
  2. Mixed-Radix Encoding     — base-17/base-31 สลับตาม position; ไม่เป็น hex
  3. Chunk Shuffle            — ชิ้นสับตำแหน่ง, reassemble ด้วย inverse index table

Anti-reversing layers (ไม่กระทบ logic):
  A. Unicode Look-alike Names — ชื่อ vars มี Cyrillic/Greek ผสม, grep/copy fail
  B. Opaque Predicates        — if-conditions ที่คำนวณซับซ้อนแต่ผลตาย true/false
  C. Phantom Functions        — functions ปลอมที่ถูก define+เรียก ใน dead branch
  D. Bogus GG API Ghosts      — pcall(gg.*) ที่ fail silently แต่ confuse analyzer
  E. Time-Lock Tautology      — os.time() check ที่ดูเหมือน expiry แต่ always true
  F. String Micro-Splitting   — strings แต่ละ chunk แบ่งเป็นชิ้น 8-20 chars concat
  G. Dead Code Injection      — math/bitwise/string ops ที่ไม่มีผล คั่น logic จริง
"""

import os
import random
import struct
import hashlib

# ── Base alphabets for mixed-radix ─────────────────────────────────────────
_B17 = '0123456789abcdefg'          # 17 chars
_B31 = '0123456789abcdefghijklmnopqrstu'   # 31 chars  (28*9=252≥256 for hi)

# ── Unicode look-alike map — used ONLY inside string literals, never in identifiers.
# LuaJ (GameGuardian's Lua engine) only accepts ASCII in variable/function names.
# Using Cyrillic/Greek in identifiers causes "unexpected symbol" parse error.
_LOOKALIKE_STR = {
    'a': ['а', 'ɑ'],   # Cyrillic а, Latin alpha
    'e': ['е', 'ε'],   # Cyrillic е, Greek epsilon
    'o': ['о', 'ο'],   # Cyrillic о, Greek omicron
    'c': ['с'],        # Cyrillic с
    'p': ['р'],        # Cyrillic р
    'x': ['х'],        # Cyrillic х
    'i': ['і'],        # Cyrillic і
    'n': ['ν'],        # Greek nu
    's': ['ѕ'],        # Cyrillic dze
}

def _make_namer(seed_int: int):
    """
    Generate unique ASCII-only variable names that are visually confusing.
    Uses only characters valid in LuaJ identifiers: [A-Za-z0-9_].
    Confusing mix of l/I/O/0/1 makes names hard to read without being invalid.
    """
    rng = random.Random(seed_int)
    used = set()
    # ASCII-only pool: digits + hex letters + visually confusing ASCII chars
    # l (lowercase L), I (uppercase i), O (uppercase o), q look alike in many fonts
    pool = list('0123456789abcdefABCDEF') + ['l', 'I', 'O', 'q', 'Q', 'lI', 'Il', 'OI', 'IO']

    def name():
        while True:
            length = rng.randint(5, 10)
            chars = []
            for _ in range(length):
                ch = rng.choice(pool)
                chars.append(ch)
            candidate = '_' + ''.join(chars)
            # Must be valid Lua identifier: ASCII only, not too long
            if candidate not in used and len(candidate) <= 20:
                used.add(candidate)
                return candidate
    return name


def _mangle_string(s: str, rng) -> str:
    """Apply Cyrillic/Greek lookalike substitution inside string content only."""
    out = []
    for ch in s:
        if ch in _LOOKALIKE_STR and rng.random() < 0.4:
            out.append(rng.choice(_LOOKALIKE_STR[ch]))
        else:
            out.append(ch)
    return ''.join(out)


# ── Fibonacci-Diffusion XOR (encode) ───────────────────────────────────────
def _fib_xor_enc(data: bytes, fa: int, fb: int, pv: int, golden: int = 0x9E) -> bytes:
    out = bytearray()
    for i, byte in enumerate(data):
        k = (fa ^ pv ^ ((i * golden) & 0xFF)) & 0xFF
        ct = byte ^ k
        out.append(ct)
        fa, fb = fb, (fa + fb + (ct & 0x0F)) % 251
        pv = ct
    return bytes(out)


# ── Mixed-Radix Encode ──────────────────────────────────────────────────────
def _to_mr(data: bytes) -> str:
    r = []
    for i, b in enumerate(data):
        if i % 2 == 0:
            r += [_B17[b // 17], _B17[b % 17]]
        else:
            r += [_B31[b // 28], _B31[b % 28]]
    return ''.join(r)


# ── Chunk Shuffle ───────────────────────────────────────────────────────────
def _chunk_shuffle(s: str, rng: random.Random):
    chunks = []
    i = 0
    while i < len(s):
        sz = rng.randint(120, 320) * 2
        sz = min(sz, len(s) - i)
        if sz % 2 == 1:
            sz += 1
        if sz == 0:
            break
        chunks.append(s[i:i+sz])
        i += sz
    order = list(range(len(chunks)))
    rng.shuffle(order)
    shuffled = [chunks[order[j]] for j in range(len(chunks))]
    inv = [0] * len(order)
    for j, o in enumerate(order):
        inv[o] = j
    return shuffled, inv


# ── Dead random string — Cyrillic/Greek lookalikes applied to content, NOT identifiers ──
def _rstr(rng, n):
    s = ''.join(rng.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(n))
    return _mangle_string(s, rng)


# ── Dead code lines ─────────────────────────────────────────────────────────
def _dead(rng, N, count=5):
    ops = [
        lambda: f"local {N()} = {rng.randint(1,9999)} * {rng.randint(1,9999)} - {rng.randint(1,999)}",
        lambda: f"local {N()} = ({rng.randint(1,255)} | {rng.randint(1,255)}) & 0xff",
        lambda: f"local {N()} = math.floor({rng.uniform(0.001, 999.9):.5f})",
        lambda: f"local {N()} = string.len(\"{_rstr(rng, rng.randint(4,10))}\")",
        lambda: f"-- {''.join(rng.choice('0123456789abcdef') for _ in range(rng.randint(12,28)))}",
        lambda: f"local {N()} = {rng.randint(1,99)} ~ {rng.randint(1,99)}",
    ]
    return [rng.choice(ops)() for _ in range(count)]


# ── Opaque predicates ───────────────────────────────────────────────────────
def _op_true(rng):
    n = rng.randint(1, 999)
    tpl = rng.randint(0, 3)
    if tpl == 0: return f"({n} * {n} - {n*n-1} == 1)"
    if tpl == 1:
        b = rng.randint(2, 40)
        return f"({rng.randint(100,999)} % {b} < {b})"
    if tpl == 2: return "(64 % 7 == 1)"
    return f"(({rng.randint(0,255)} | 1) >= 1)"

def _op_false(rng):
    n = rng.randint(1, 999)
    tpl = rng.randint(0, 2)
    if tpl == 0: return f"({n} == {n+1})"
    if tpl == 1:
        a = rng.randint(2, 50)
        return f"({a*a} < {a})"
    return "(1 == 2)"


# ── Phantom functions (dead branches) ──────────────────────────────────────
def _phantoms(rng, N, count=3):
    lines = []
    for _ in range(count):
        fn = N(); a = N(); b = N(); rv = N()
        v1 = rng.randint(1, 999); v2 = rng.randint(1, 999)
        lines += [
            f"local function {fn}({a}, {b})",
            f"  return {a} + {b} * {rng.randint(1,7)}",
            f"end",
            f"if {_op_false(rng)} then",
            f"  local {rv} = {fn}({v1}, {v2})",
            f"end",
        ]
    return lines


# ── Bogus GG API ghosts ─────────────────────────────────────────────────────
def _gg_ghosts(rng, N):
    calls = [
        'gg.getTargetPackage()',
        'gg.getRanges(gg.REGION_C_HEAP)',
        'gg.searchNumber("0", gg.TYPE_DWORD)',
        'gg.getResults(1)',
        'gg.clearResults()',
    ]
    chosen = rng.sample(calls, k=3)
    lines = []
    for c in chosen:
        lines.append(f"local {N()} = pcall(function() return {c} end)")
    return lines


# ── Time-lock tautology ─────────────────────────────────────────────────────
def _timelock(rng, N):
    mod = rng.randint(100, 9999); add = rng.randint(1, 99)
    t = N(); ck = N()
    return [
        f"local {t} = os.time()",
        f"local {ck} = ({t} % {mod}) + {add} >= {add}",
        f"if not {ck} then return end",
    ]


# ── Micro-split a string into short concat pieces ──────────────────────────
def _split_str(s: str, rng, N, lines_out):
    """Write 'local <var> = <many short strings concatenated>' into lines_out, return var name."""
    tbl = N(); out_var = N()
    lines_out.append(f"local {tbl} = {{}}")
    i = 0; idx = 1
    while i < len(s):
        sz = rng.randint(8, 22)
        sz = min(sz, len(s) - i)
        piece = s[i:i+sz]
        escaped = piece.replace('\\', '\\\\').replace('"', '\\"')
        lines_out.append(f'{tbl}[{idx}] = "{escaped}"')
        if rng.random() < 0.25:
            lines_out.append(f"local {N()} = {rng.randint(1,999)}")
        i += sz; idx += 1
    lines_out.append(f"local {out_var} = table.concat({tbl})")
    return out_var


# ═══════════════════════════════════════════════════════════════════════════
# PUBLIC: obfuscate_bytecode
# ═══════════════════════════════════════════════════════════════════════════

def obfuscate_bytecode(bytecode: bytes) -> bytes:
    """
    Input:  bytes (Lua source or bytecode)
    Output: obfuscated Lua source bytes, runnable on GameGuardian Lua
    """
    seed = struct.unpack('>Q', os.urandom(8))[0]
    rng  = random.Random(seed)
    N    = _make_namer(rng.randint(0, 0xFFFFFFFF))
    golden = 0x9E

    # Init Fibonacci state (random)
    fa = rng.randint(1, 200)
    fb = rng.randint(1, 200)
    pv = rng.randint(0, 255)

    # ── Encode pipeline ──────────────────────────────────────────────────
    enc    = _fib_xor_enc(bytecode, fa, fb, pv, golden)
    mr_str = _to_mr(enc)
    shuffled_chunks, inv_order = _chunk_shuffle(mr_str, rng)
    n_chunks = len(shuffled_chunks)

    # ── Build Lua source ─────────────────────────────────────────────────
    L = []  # lines

    # Decoy header
    L += [
        f"-- LuaR v{rng.randint(3,9)}.{rng.randint(0,9)}.{rng.randint(100,999)}",
        f"-- build {rng.randint(100000,999999)} "
        f"checksum {format(rng.randint(0, 0xFFFFFFFF), '08x')}",
        f"-- {_rstr(rng, 40)}",
    ]

    # Bogus GG ghosts (confuse static analysis of gg.* usage)
    L += _gg_ghosts(rng, N)

    # Time-lock tautology
    L += _timelock(rng, N)

    # Dead block 1
    L += _dead(rng, N, 5)

    # Phantom functions in dead branches
    L += _phantoms(rng, N, 3)

    # Dead block 2
    L += _dead(rng, N, 4)

    # ── Chunk table ──────────────────────────────────────────────────────
    v_chunks = N()
    L.append(f"local {v_chunks} = {{}}")

    for idx, chunk in enumerate(shuffled_chunks):
        sub_var = _split_str(chunk, rng, N, L)
        L.append(f"{v_chunks}[{idx+1}] = {sub_var}")
        if rng.random() < 0.35:
            L += _dead(rng, N, 2)

    # ── Inverse order table ──────────────────────────────────────────────
    v_inv = N()
    inv_parts = ",".join(str(x+1) for x in inv_order)
    L.append(f"local {v_inv} = {{{inv_parts}}}")

    # Dead block 3
    L += _dead(rng, N, 4)

    # Anti-debug opaque trap
    L += [
        f"if {_op_false(rng)} then",
        f"  local {N()} = nil",
        f"end",
    ]

    # ── Reassemble chunks in correct order ───────────────────────────────
    v_buf = N(); v_mr = N(); v_loop = N()
    L += [
        f"local {v_buf} = {{}}",
        f"for {v_loop}=1,{n_chunks} do",
        f"  {v_buf}[{v_inv}[{v_loop}]] = {v_chunks}[{v_loop}]",
        f"end",
        f"local {v_mr} = table.concat({v_buf})",
    ]

    # ── Mixed-radix decode → byte array ─────────────────────────────────
    v_b17 = N(); v_b31 = N()
    v_raw = N(); v_ri  = N(); v_bi = N()

    # Split the alphabet strings too (extra obfuscation)
    b17_var = _split_str(_B17, rng, N, L)
    b31_var = _split_str(_B31, rng, N, L)
    L += [
        f"local {v_b17} = {b17_var}",
        f"local {v_b31} = {b31_var}",
        f"local {v_raw} = {{}}",
        f"local {v_ri}  = 1",
        f"local {v_bi}  = 0",
        f"local _mri = 1",
        f"while _mri + 1 <= #{v_mr} do",
        f"  if {v_bi} % 2 == 0 then",
        f"    local _h = {v_b17}:find({v_mr}:sub(_mri,_mri),1,true)-1",
        f"    local _l = {v_b17}:find({v_mr}:sub(_mri+1,_mri+1),1,true)-1",
        f"    {v_raw}[{v_ri}] = string.char(_h*17+_l)",
        f"  else",
        f"    local _h = {v_b31}:find({v_mr}:sub(_mri,_mri),1,true)-1",
        f"    local _l = {v_b31}:find({v_mr}:sub(_mri+1,_mri+1),1,true)-1",
        f"    {v_raw}[{v_ri}] = string.char(_h*28+_l)",
        f"  end",
        f"  {v_ri} = {v_ri}+1",
        f"  {v_bi} = {v_bi}+1",
        f"  _mri = _mri+2",
        f"end",
    ]

    # Dead block 4
    L += _dead(rng, N, 3)

    # ── Fibonacci-Diffusion XOR decode ───────────────────────────────────
    v_fa  = N(); v_fb  = N(); v_pv  = N()
    v_dec = N(); v_ii  = N()
    v_ct  = N(); v_k   = N(); v_pt  = N(); v_nfb = N()

    L += [
        f"local {v_fa} = {fa}",
        f"local {v_fb} = {fb}",
        f"local {v_pv} = {pv}",
        f"local {v_dec} = {{}}",
        f"for {v_ii}=1,#{v_raw} do",
        f"  local {v_ct} = string.byte({v_raw}[{v_ii}])",
        f"  local {v_k} = ({v_fa} ~ {v_pv} ~ (({v_ii}-1) * {golden} & 0xFF)) & 0xFF",
        f"  local {v_pt} = {v_ct} ~ {v_k}",
        f"  {v_dec}[{v_ii}] = string.char({v_pt})",
        f"  local {v_nfb} = ({v_fa} + {v_fb} + ({v_ct} & 0x0f)) % 251",
        f"  {v_fa} = {v_fb}",
        f"  {v_fb} = {v_nfb}",
        f"  {v_pv} = {v_ct}",
        f"end",
    ]

    # Dead block 5
    L += _dead(rng, N, 3)

    # ── load() and execute ───────────────────────────────────────────────
    v_src = N(); v_fn = N(); v_err = N()
    L += [
        f"local {v_src} = table.concat({v_dec})",
        f"local {v_fn}, {v_err} = load({v_src})",
        f"if {v_fn} then",
        f"  {v_fn}()",
        f"elseif {_op_false(rng)} then",
        f"  print({v_err})",
        f"end",
    ]

    return "\n".join(L).encode("utf-8")


# ── Quick self-test ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    payload = b'print("LuaR v3 obfuscation works!") for i=1,3 do print(i*i) end'
    print("[*] Obfuscating...")
    result = obfuscate_bytecode(payload)
    print(f"[+] Output: {len(result):,} bytes")
    print("[*] Preview (first 600 chars):")
    print(result[:600].decode("utf-8", errors="replace"))
    out_path = "/home/claude/test_v3.lua"
    with open(out_path, "wb") as f:
        f.write(result)
    print(f"\n[+] Saved: {out_path}")
