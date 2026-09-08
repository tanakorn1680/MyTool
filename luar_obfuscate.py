"""
LuaR Obfuscator — rewritten for correctness + maximum difficulty
"""

import os, random, struct, hashlib

_B17 = '0123456789abcdefg'
_B31 = '0123456789abcdefghijklmnopqrstu'

def _make_namer(seed_int):
    rng = random.Random(seed_int)
    used = set()
    confuse = 'lIO0' 
    def name():
        while True:
            n = rng.randint(6,12)
            chars = [rng.choice(confuse + 'abcdefABCDEF0123456789') for _ in range(n)]
            c = '_' + ''.join(chars)
            if c not in used:
                used.add(c)
                return c
    return name

def _rng_str(rng, n):
    return ''.join(rng.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(n))

def _op_false(rng):
    n = rng.randint(2,999)
    return f'({n} == {n+1})'

def _op_true(rng):
    n = rng.randint(1,999)
    return f'({n} == {n})'

def _fib_xor_enc(data, fa, fb, pv, golden=0x9E):
    out = bytearray()
    for i, b in enumerate(data):
        k = (fa ^ pv ^ ((i * golden) & 0xFF)) & 0xFF
        ct = b ^ k
        out.append(ct)
        fa, fb = fb, (fa + fb + (ct & 0x0F)) % 251
        pv = ct
    return bytes(out)

def _to_mr(data):
    r = []
    for i, b in enumerate(data):
        if i % 2 == 0:
            r += [_B17[b // 17], _B17[b % 17]]
        else:
            r += [_B31[b // 28], _B31[b % 28]]
    return ''.join(r)

def _chunk_shuffle(s, rng):
    chunks, i = [], 0
    while i < len(s):
        sz = min(rng.randint(120,320)*2, len(s)-i)
        if sz % 2 == 1: sz += 1
        if sz == 0: break
        chunks.append(s[i:i+sz])
        i += sz
    order = list(range(len(chunks)))
    rng.shuffle(order)
    inv = [0]*len(order)
    for j,o in enumerate(order): inv[o] = j
    shuffled = [chunks[order[j]] for j in range(len(chunks))]
    return shuffled, inv


def obfuscate_bytecode(src: bytes) -> bytes:
    seed = struct.unpack('>Q', os.urandom(8))[0]
    rng  = random.Random(seed)
    N    = _make_namer(rng.randint(0, 0xFFFFFFFF))
    golden = 0x9E

    fa = rng.randint(1,200)
    fb = rng.randint(1,200)
    pv = rng.randint(0,255)

    enc            = _fib_xor_enc(src, fa, fb, pv, golden)
    mr_str         = _to_mr(enc)
    chunks, inv    = _chunk_shuffle(mr_str, rng)
    n_chunks       = len(chunks)
    # order[inv[o]] = o  →  buf[order[i]] = chunks[i]  →  correct reassemble
    order = [0]*n_chunks
    for o in range(n_chunks): order[inv[o]] = o

    L = []  # lines ทั้งหมด

    # ── header comments ──────────────────────────────────────────────────
    L += [
        f"-- {_rng_str(rng,40)}",
        f"-- build {rng.randint(100000,999999)} checksum {format(rng.randint(0,0xFFFFFFFF),'08x')}",
    ]

    # ── open single do block ──────────────────────────────────────────────
    L.append("do")

    def e(line, indent=1):
        L.append("  "*indent + line)

    # ── bogus gg calls (fail silently) ───────────────────────────────────
    gg_calls = ['gg.getTargetPackage()','gg.getRanges(gg.REGION_C_HEAP)',
                'gg.clearResults()','gg.getResults(1)']
    for c in rng.sample(gg_calls, 2):
        e(f"local {N()} = pcall(function() return {c} end)")

    # ── timelock tautology ───────────────────────────────────────────────
    vt = N()
    e(f"local {vt} = os.time()")
    e(f"if ({vt} % {rng.randint(100,9999)}) + 1 < 1 then return end")

    # ── dead locals ──────────────────────────────────────────────────────
    for _ in range(4):
        e(f"local {N()} = {rng.randint(1,999)} * {rng.randint(1,999)}")

    # ── phantom functions in dead branches (self-contained, balanced) ────
    for _ in range(3):
        fn = N(); a = N(); b = N()
        e(f"local function {fn}({a},{b})")
        e(f"  return {a}+{b}*{rng.randint(1,7)}", indent=1)
        e(f"end")
        e(f"if {_op_false(rng)} then")
        e(f"  {fn}({rng.randint(1,99)},{rng.randint(1,99)})")
        e(f"end")

    # ── more dead locals ─────────────────────────────────────────────────
    for _ in range(3):
        e(f"-- {_rng_str(rng,24)}")

    # ── chunk table ──────────────────────────────────────────────────────
    vChunks = N()
    e(f"local {vChunks} = {{}}")

    for idx, chunk in enumerate(chunks):
        # แต่ละ chunk อยู่ใน do...end ของตัวเอง
        e(f"do")
        tmp = N()
        e(f"  local {tmp} = {{}}", indent=1)
        ci = 0; pi = 1
        while ci < len(chunk):
            sz = min(rng.randint(8,22), len(chunk)-ci)
            piece = chunk[ci:ci+sz]
            escaped = piece.replace('\\','\\\\').replace('"','\\"')
            e(f"  {tmp}[{pi}] = \"{escaped}\"", indent=1)
            ci += sz; pi += 1
        e(f"  {vChunks}[{idx+1}] = table.concat({tmp})", indent=1)
        e(f"end")  # ← ปิด do chunk
        if rng.random() < 0.3:
            e(f"-- {_rng_str(rng,20)}")

    # ── order table (buf[order[i]] = chunks[i] → correct reassemble) ────
    vOrd = N()
    e(f"local {vOrd} = {{{','.join(str(x+1) for x in order)}}}")

    # ── reassemble ───────────────────────────────────────────────────────
    vBuf = N(); vMR = N(); vi = N()
    e(f"local {vBuf} = {{}}")
    e(f"for {vi}=1,{n_chunks} do")
    e(f"  {vBuf}[{vOrd}[{vi}]] = {vChunks}[{vi}]")
    e(f"end")
    e(f"local {vMR} = table.concat({vBuf})")

    # ── mixed-radix decode ───────────────────────────────────────────────
    vB17=N(); vB31=N(); vRaw=N()
    vRI=N(); vBI=N(); vMRI=N(); vH=N(); vVL=N()
    e(f"local {vB17} = \"{_B17}\"")
    e(f"local {vB31} = \"{_B31}\"")
    e(f"local {vRaw} = {{}}")
    e(f"local {vRI} = 1")
    e(f"local {vBI} = 0")
    e(f"local {vMRI} = 1")
    e(f"local {vH} = 0")
    e(f"local {vVL} = 0")
    e(f"while {vMRI}+1 <= #{vMR} do")
    e(f"  if {vBI}%2==0 then")
    e(f"    {vH} = {vB17}:find({vMR}:sub({vMRI},{vMRI}),1,true)-1")
    e(f"    {vVL} = {vB17}:find({vMR}:sub({vMRI}+1,{vMRI}+1),1,true)-1")
    e(f"    {vRaw}[{vRI}] = string.char({vH}*17+{vVL})")
    e(f"  else")
    e(f"    {vH} = {vB31}:find({vMR}:sub({vMRI},{vMRI}),1,true)-1")
    e(f"    {vVL} = {vB31}:find({vMR}:sub({vMRI}+1,{vMRI}+1),1,true)-1")
    e(f"    {vRaw}[{vRI}] = string.char({vH}*28+{vVL})")
    e(f"  end")
    e(f"  {vRI}={vRI}+1")
    e(f"  {vBI}={vBI}+1")
    e(f"  {vMRI}={vMRI}+2")
    e(f"end")

    # ── fibonacci XOR decode ─────────────────────────────────────────────
    vFA=N(); vFB=N(); vPV=N(); vDec=N()
    vII=N(); vCT=N(); vK=N(); vPT=N(); vNFB=N()
    e(f"local {vFA} = {fa}")
    e(f"local {vFB} = {fb}")
    e(f"local {vPV} = {pv}")
    e(f"local {vDec} = {{}}")
    e(f"local {vII} = 0")
    e(f"local {vCT} = 0")
    e(f"local {vK} = 0")
    e(f"local {vPT} = 0")
    e(f"local {vNFB} = 0")
    e(f"for {vII}=1,#{vRaw} do")
    e(f"  {vCT} = string.byte({vRaw}[{vII}])")
    e(f"  {vK} = ({vFA} ~ {vPV} ~ (({vII}-1)*{golden}&0xFF))&0xFF")
    e(f"  {vPT} = {vCT} ~ {vK}")
    e(f"  {vDec}[{vII}] = string.char({vPT})")
    e(f"  {vNFB} = ({vFA}+{vFB}+({vCT}&0x0f))%251")
    e(f"  {vFA} = {vFB}")
    e(f"  {vFB} = {vNFB}")
    e(f"  {vPV} = {vCT}")
    e(f"end")

    # ── load and execute ─────────────────────────────────────────────────
    vSrc=N(); vFn=N(); vErr=N()
    e(f"local {vSrc} = table.concat({vDec})")
    e(f"local {vFn},{vErr} = load({vSrc})")
    e(f"if {vFn} then")
    e(f"  {vFn}()")
    e(f"end")

    # ── close outer do ───────────────────────────────────────────────────
    L.append("end")

    # ── verify balance before returning ─────────────────────────────────
    code = "\n".join(L)
    depth = 0
    for line in L:
        s = line.strip()
        if s == "do": depth += 1
        elif s.endswith(" do") and ("for " in s or "while " in s): depth += 1
        elif s.endswith(" then") and s.startswith("if "): depth += 1
        elif s.startswith("local function "): depth += 1
        elif s == "end": depth -= 1
    assert depth == 0, f"do/end imbalance: depth={depth}"

    return code.encode("utf-8")
