"""
LuaR Obfuscate v5 — Binary-looking Lua output

Pipeline:
  1. User .lua → luac5.3 → Lua 5.3 bytecode (payload)
  2. LFSR encrypt payload, anti-tamper FNV seed hiding
  3. Full loader (Lua source) → luac5.3 → stage-2 bytecode
  4. Stage-2 bytecode → table of string.char() chunks
  5. Output: single-line Lua script that looks like binary garbage

Output format:
  local _t={} _t[1]=string.char(27,76,117,97,83,...) _t[2]=... load(table.concat(_t))()

The file starts with 27,76,117,97,83 = 0x1b,L,u,a,S = Lua 5.3 bytecode magic
Visually indistinguishable from binary .lua files like SCBI.
"""

import os, random, struct, subprocess, tempfile

TAPS = 0x80200003  # 32-bit Galois LFSR taps

# ─── LFSR stream cipher (bijective) ──────────────────────────────────────────
def _lfsr_enc(data: bytes, seed: int) -> bytes:
    st = (seed & 0xFFFFFFFF) or 1
    out = []
    for b in data:
        lsb = st & 1
        st = ((st >> 1) ^ (TAPS if lsb else 0)) & 0xFFFFFFFF
        out.append((b + (st & 0xFF)) & 0xFF)
    return bytes(out)

def _lfsr_dec_verify(enc: bytes, seed: int) -> bytes:
    st = (seed & 0xFFFFFFFF) or 1
    out = []
    for b in enc:
        lsb = st & 1
        st = ((st >> 1) ^ (TAPS if lsb else 0)) & 0xFFFFFFFF
        out.append((b - (st & 0xFF)) & 0xFF)
    return bytes(out)

# ─── FNV-1a 32-bit ───────────────────────────────────────────────────────────
def _fnv32(data: bytes) -> int:
    h = 2166136261
    for b in data:
        h = ((h ^ b) * 16777619) & 0xFFFFFFFF
    return h

# ─── luac helper ─────────────────────────────────────────────────────────────
def _find_luac():
    import shutil
    for c in ["luac5.3", "luac5.4", "luac"]:
        path = shutil.which(c)
        if path:
            return path
    return None

def _compile(lua_source: bytes, luac: str) -> bytes:
    """Compile Lua source to bytecode. Returns source unchanged on failure."""
    with tempfile.NamedTemporaryFile(suffix=".lua", delete=False) as f:
        f.write(lua_source)
        sp = f.name
    op = sp + "c"
    try:
        r = subprocess.run([luac, "-o", op, sp], capture_output=True, timeout=15)
        if r.returncode != 0:
            return lua_source  # syntax error — use source
        return open(op, "rb").read()
    except Exception:
        return lua_source
    finally:
        for p in [sp, op]:
            try: os.unlink(p)
            except: pass

def _is_bytecode(data: bytes) -> bool:
    return data[:3] in (b'\x1bLu', b'\x1bLJ')

# ─── Name mangler ─────────────────────────────────────────────────────────────
def _make_namer(seed_int):
    rng = random.Random(seed_int)
    used = set()
    POOL = "lI10OoQ"
    def name():
        while True:
            n = "_" * rng.randint(1, 3) + "".join(rng.choice(POOL) for _ in range(rng.randint(5, 9)))
            if n not in used:
                used.add(n)
                return n
    return name

# ─── Opaque predicates ───────────────────────────────────────────────────────
def _op_true(rng, N):
    n = rng.randint(100, 9999)
    vn = N()
    return f"local {vn}={n}", f"(({vn}*({vn}+1))%2==0)"

def _op_false(rng, N):
    n = rng.randint(1, 999)
    vn = N()
    return f"local {vn}={n}", f"(({vn}*{vn})<0)"

def _dead(rng, N):
    setup_f, cond_f = _op_false(rng, N)
    vd = N()
    return f"{setup_f} if {cond_f} then local {vd}={rng.randint(10,9999)} {vd}={vd}*{rng.randint(2,99)} end"

# ─── Generate inner loader Lua source ────────────────────────────────────────
def _make_loader(enc: bytes, stored_seed: int, rng: random.Random) -> bytes:
    """
    Produce Lua source that:
      1. Reassembles encrypted chunks (in shuffled order)
      2. Recovers cipher seed via FNV checksum (anti-tamper)
      3. LFSR-decrypts to original bytecode
      4. Calls load() and runs it
    This source is then compiled to bytecode (stage-2).
    """
    N = _make_namer(rng.randint(0, 0xFFFFFFFF))

    # Chunk + shuffle encrypted data
    CHUNK = rng.randint(200, 350)
    chunks = [enc[i:i+CHUNK] for i in range(0, len(enc), CHUNK)]
    nc = len(chunks)

    order = list(range(nc))
    rng.shuffle(order)
    inv = [0] * nc
    for si, oi in enumerate(order):
        inv[oi] = si

    # Variable names
    vC  = [N() for _ in range(nc)]  # chunk vars (shuffled order)
    vT  = N()   # chunk pointer table
    vV  = N()   # inverse perm
    vB  = N()   # reassembled buffer
    vH  = N()   # FNV hash
    vS  = N()   # cipher seed
    vSt = N()   # LFSR state
    vO  = N()   # output chars
    vF  = N()   # loaded fn
    vI  = N()   # loop var

    L = []

    # Outer always-true opaque predicate
    s_t, c_t = _op_true(rng, N)
    L.append(s_t)
    L.append(f"if {c_t} then")

    # Dead code
    L.append("  " + _dead(rng, N))

    # Chunk vars in shuffled order (vC[si] holds chunks[order[si]])
    for si in range(nc):
        oi = order[si]
        nums = ",".join(str(b) for b in chunks[oi])
        L.append(f"  local {vC[si]}={{{nums}}}")

    L.append("  " + _dead(rng, N))

    # Inverse permutation table (0-based)
    L.append(f"  local {vV}={{{','.join(str(x) for x in inv)}}}")

    # Pointer table: vT[si+1] = vC[si]  (Lua 1-based)
    tbl = ",".join(vC[si] for si in range(nc))
    L.append(f"  local {vT}={{{tbl}}}")

    # Reassemble in original order: iterate oi=1..nc, get si=inv[oi], read vT[si+1]
    L.append(f"  local {vB}={{}}")
    L.append(f"  local {vI}=0")
    L.append(f"  for _oi=1,{nc} do")
    L.append(f"    local _si={vV}[_oi]")
    L.append(f"    local _ch={vT}[_si+1]")
    L.append(f"    for _j=1,#_ch do {vI}={vI}+1 {vB}[{vI}]=_ch[_j] end")
    L.append(f"  end")

    # FNV-1a checksum to recover seed
    L.append(f"  local {vH}=2166136261")
    L.append(f"  for {vI}=1,#{vB} do")
    L.append(f"    {vH}=({vH}~{vB}[{vI}])*16777619&0xFFFFFFFF")
    L.append(f"  end")
    L.append(f"  local {vS}=({stored_seed}~{vH})&0xFFFFFFFF")
    L.append(f"  if {vS}==0 then {vS}=1 end")

    L.append("  " + _dead(rng, N))

    # LFSR decrypt
    L.append(f"  local {vSt}={vS}")
    L.append(f"  local {vO}={{}}")
    L.append(f"  for {vI}=1,#{vB} do")
    L.append(f"    local _l={vSt}&1")
    L.append(f"    {vSt}=({vSt}>>1)~(_l==1 and {TAPS} or 0)")
    L.append(f"    {vSt}={vSt}&0xFFFFFFFF")
    L.append(f"    {vO}[{vI}]=string.char(({vB}[{vI}]-({vSt}&255))&255)")
    L.append(f"  end")

    # Load and run
    L.append(f"  local {vF}=load(table.concat({vO}))")
    L.append(f"  if {vF} then {vF}() end")
    L.append(f"end")

    return "\n".join(L).encode("utf-8")

# ─── Encode bytes as Lua bootstrap (single line, table of string.char) ───────
def _encode_as_bootstrap(bc: bytes) -> str:
    """
    Encode bytecode as:
      local _t={} _t[1]=string.char(N,...) _t[2]=... load(table.concat(_t))()
    All on one line. Looks like binary garbage.
    string.char() is limited to ~250 args in Lua, so we chunk at 200.
    """
    LIMIT = 200
    parts = ["local _t={}"]
    for i, start in enumerate(range(0, len(bc), LIMIT)):
        chunk = bc[start:start+LIMIT]
        nums = ",".join(str(b) for b in chunk)
        parts.append(f"_t[{i+1}]=string.char({nums})")
    parts.append("load(table.concat(_t))()")
    return " ".join(parts)

# ─── Main entry point ─────────────────────────────────────────────────────────
def obfuscate_bytecode(lua_source: bytes) -> bytes:
    """
    Input:  Lua source text OR already-compiled bytecode
    Output: Single-line Lua script that looks like binary garbage.
            Starts with Lua 5.3 bytecode magic bytes (27,76,117,97,83,...).
            Runs correctly on GameGuardian (Lua 5.3+).
    """
    rng  = random.Random(struct.unpack(">Q", os.urandom(8))[0])
    luac = _find_luac()

    # ── Step 1: Compile user script to bytecode ──────────────────────────────
    if _is_bytecode(lua_source):
        payload_bc = lua_source
    elif luac:
        payload_bc = _compile(lua_source, luac)
    else:
        payload_bc = lua_source  # no luac — use source as payload

    # ── Step 2: LFSR-encrypt payload bytecode ────────────────────────────────
    raw_seed = struct.unpack(">I", os.urandom(4))[0] or 0xDEADBEEF
    enc = _lfsr_enc(payload_bc, raw_seed)
    assert _lfsr_dec_verify(enc, raw_seed) == payload_bc, "LFSR verify failed"

    # ── Step 3: Anti-tamper — hide seed behind FNV checksum ─────────────────
    stored_seed = (raw_seed ^ _fnv32(enc)) & 0xFFFFFFFF

    # ── Step 4: Generate inner loader Lua source ─────────────────────────────
    loader_src = _make_loader(enc, stored_seed, rng)

    # ── Step 5: Compile loader to bytecode (stage-2) ─────────────────────────
    if luac:
        loader_bc = _compile(loader_src, luac)
        if not _is_bytecode(loader_bc):
            # Compilation failed somehow — use source as fallback
            loader_bc = loader_src
    else:
        loader_bc = loader_src

    # ── Step 6: Encode as single-line bootstrap ──────────────────────────────
    bootstrap = _encode_as_bootstrap(loader_bc)
    return bootstrap.encode("utf-8")
