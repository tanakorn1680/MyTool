"""
LuaR Obfuscate v6 — Triple-stage, GG-keyed, stripped, no 'load' keyword

Design:
  encrypt seed = FNV(nonce_bytes)       [Python, stored implicitly via nonce]
  decrypt seed = FNV(pkg_bytes+nonce)   [Lua runtime via gg.getTargetPackage()]
  
  เมื่อ pkg='' (นอก GG):  seed = FNV(nonce_bytes) = encrypt seed → decrypt ได้ [dev/test]
  เมื่อ pkg='com.ea...' (ใน GG):  seed = FNV(pkg+nonce) ≠ encrypt seed → decrypt ผิด
  
  → ในการใช้งานจริง: ต้องรู้ package name ของเกมที่ target จึงจะถอดได้

Anti-keyword:
  ไม่มีคำว่า 'load' ปรากฏในไฟล์ output เลย
  ใช้ string.char(108,111,97,100) แทน 'load'
  ใช้ string.char(116,97,98,108,101) แทน 'table'
"""

import os, random, struct, subprocess, tempfile

TAPS = 0x80200003

# ─── Cipher ───────────────────────────────────────────────────────────────────
def _lfsr_enc(data: bytes, seed: int) -> bytes:
    st = (seed & 0xFFFFFFFF) or 1
    out = []
    for b in data:
        lsb = st & 1
        st = ((st >> 1) ^ (TAPS if lsb else 0)) & 0xFFFFFFFF
        out.append((b + (st & 0xFF)) & 0xFF)
    return bytes(out)

def _fnv32(data: bytes) -> int:
    h = 2166136261
    for b in data:
        h = ((h ^ b) * 16777619) & 0xFFFFFFFF
    return h & 0xFFFFFFFF or 1

# ─── luac ─────────────────────────────────────────────────────────────────────
def _find_luac():
    import shutil
    for c in ["luac5.3", "luac5.4", "luac"]:
        p = shutil.which(c)
        if p: return p
    return None

def _compile(src: bytes, luac: str, strip=True) -> bytes:
    with tempfile.NamedTemporaryFile(suffix=".lua", delete=False) as f:
        f.write(src); sp = f.name
    op = sp + "c"
    try:
        args = [luac] + (["-s"] if strip else []) + ["-o", op, sp]
        r = subprocess.run(args, capture_output=True, timeout=15)
        if r.returncode != 0: return src
        return open(op, "rb").read()
    except Exception: return src
    finally:
        for p in [sp, op]:
            try: os.unlink(p)
            except: pass

def _is_bc(d: bytes) -> bool:
    return d[:3] in (b'\x1bLu', b'\x1bLJ')

# ─── Names ────────────────────────────────────────────────────────────────────
def _namer(seed):
    rng = random.Random(seed); used = set()
    def name():
        while True:
            n = "_"*rng.randint(1,3)+"".join(rng.choice("lI10OoQ") for _ in range(rng.randint(5,9)))
            if n not in used: used.add(n); return n
    return name

def _dead(rng, N, ind=""):
    vn=N(); vd=N(); n=rng.randint(1,999)
    return f"{ind}local {vn}={n} if(({vn}*{vn})<0)then local {vd}={rng.randint(10,9999)} {vd}={vd}*{rng.randint(2,99)} end"

# ─── String literal encoder (hides keywords) ──────────────────────────────────
def _hide_str(s: str) -> str:
    """แปลง string literal เป็น string.char() เพื่อซ่อน keyword"""
    nums = ",".join(str(ord(c)) for c in s)
    return f"string.char({nums})"

# ─── Inner loader (Lua source → compiled bytecode) ────────────────────────────
def _make_inner(enc: bytes, nonce: int, rng: random.Random) -> bytes:
    N = _namer(rng.randint(0,0xFFFFFFFF))
    CHUNK = rng.randint(180,300)
    chunks = [enc[i:i+CHUNK] for i in range(0,len(enc),CHUNK)]
    nc = len(chunks)
    order = list(range(nc)); rng.shuffle(order)
    inv = [0]*nc
    for si,oi in enumerate(order): inv[oi]=si

    vC=[N() for _ in range(nc)]
    vT=N(); vV=N(); vB=N(); vH=N(); vS=N(); vSt=N(); vO=N(); vF=N(); vI=N(); vPk=N()

    nonce_bytes = [(nonce>>(8*i))&0xFF for i in range(4)]

    L=[]
    n_op=rng.randint(100,9999); vop=N()
    L.append(f"local {vop}={n_op} if(({vop}*({vop}+1))%2==0)then")
    L.append("  "+_dead(rng,N))

    for si in range(nc):
        nums=",".join(str(b) for b in chunks[order[si]])
        L.append(f"  local {vC[si]}={{{nums}}}")

    L.append("  "+_dead(rng,N))
    L.append(f"  local {vV}={{{','.join(str(x) for x in inv)}}}")
    L.append(f"  local {vT}={{{','.join(vC[si] for si in range(nc))}}}")
    L.append(f"  local {vB}={{}}")
    L.append(f"  local {vI}=0")
    L.append(f"  for _oi=1,{nc} do")
    L.append(f"    local _ch={vT}[{vV}[_oi]+1]")
    L.append(f"    for _j=1,#_ch do {vI}={vI}+1 {vB}[{vI}]=_ch[_j] end")
    L.append(f"  end")

    # GG binding: seed = FNV(pkg_bytes + nonce_bytes)
    # pkg = '' นอก GG → seed = FNV(nonce_bytes) = Python encrypt seed ✓
    # pkg = 'com.xxx' ใน GG → seed ≠ encrypt seed → decrypt ผิด ✓
    L.append(f"  local {vPk}=''")
    L.append(f"  if gg then")
    L.append(f"    local _ok,_r=pcall(function()return gg.getTargetPackage()end)")
    L.append(f"    if _ok and _r then {vPk}=tostring(_r) end")
    L.append(f"  end")
    L.append(f"  local {vH}=2166136261")
    L.append(f"  for _i=1,#{vPk} do {vH}=({vH}~{vPk}:byte(_i))*16777619&0xFFFFFFFF end")
    nc_str = ",".join(str(b) for b in nonce_bytes)
    L.append(f"  for _,_b in ipairs({{{nc_str}}}) do {vH}=({vH}~_b)*16777619&0xFFFFFFFF end")
    L.append(f"  local {vS}={vH}&0xFFFFFFFF")
    L.append(f"  if {vS}==0 then {vS}=1 end")
    L.append("  "+_dead(rng,N))

    # LFSR decrypt
    L.append(f"  local {vSt}={vS}")
    L.append(f"  local {vO}={{}}")
    L.append(f"  for {vI}=1,#{vB} do")
    L.append(f"    local _l={vSt}&1")
    L.append(f"    {vSt}=({vSt}>>1)~(_l==1 and {TAPS} or 0)")
    L.append(f"    {vSt}={vSt}&0xFFFFFFFF")
    L.append(f"    {vO}[{vI}]=string.char(({vB}[{vI}]-({vSt}&255))&255)")
    L.append(f"  end")

    # ซ่อน 'load' และ 'table' ด้วย rawget + _ENV
    vRL=N(); vRT=N()
    # 'load' = char(108,111,97,100)  'table' = char(116,97,98,108,101)
    L.append(f"  local {vRL}=rawget(_ENV,{_hide_str('load')})")
    L.append(f"  local {vRT}=rawget(_ENV,{_hide_str('table')})")
    L.append(f"  local {vF}={vRL}({vRT}.concat({vO}))")
    L.append(f"  if {vF} then {vF}() end")
    L.append(f"end")

    return "\n".join(L).encode("utf-8")

# ─── Outer loader ─────────────────────────────────────────────────────────────
def _make_outer(loader_bc: bytes, rng: random.Random) -> bytes:
    N = _namer(rng.randint(0,0xFFFFFFFF))
    vT=N(); vRL=N(); vRT=N()
    LIMIT=200
    parts=[f"local {vT}={{}}"]
    for i,start in enumerate(range(0,len(loader_bc),LIMIT)):
        chunk=loader_bc[start:start+LIMIT]
        nums=",".join(str(b) for b in chunk)
        parts.append(f"{vT}[{i+1}]=string.char({nums})")
    parts.append(f"local {vRL}=rawget(_ENV,{_hide_str('load')})")
    parts.append(f"local {vRT}=rawget(_ENV,{_hide_str('table')})")
    parts.append(f"{vRL}({vRT}.concat({vT}))()")
    return (" ".join(parts)).encode("utf-8")

# ─── Bootstrap ────────────────────────────────────────────────────────────────
def _bootstrap(outer_bc: bytes) -> str:
    LIMIT=200
    if len(outer_bc)<=LIMIT:
        nums=",".join(str(b) for b in outer_bc)
        return f"rawget(_ENV,{_hide_str('load')})(string.char({nums}))()"
    parts=["local _t={}"]
    for i,start in enumerate(range(0,len(outer_bc),LIMIT)):
        chunk=outer_bc[start:start+LIMIT]
        nums=",".join(str(b) for b in chunk)
        parts.append(f"_t[{i+1}]=string.char({nums})")
    parts.append(f"rawget(_ENV,{_hide_str('load')})(rawget(_ENV,{_hide_str('table')}).concat(_t))()")
    return " ".join(parts)

# ─── Main ─────────────────────────────────────────────────────────────────────
def obfuscate_bytecode(lua_source: bytes) -> bytes:
    rng  = random.Random(struct.unpack(">Q", os.urandom(8))[0])
    luac = _find_luac()

    # Compile user script
    if _is_bc(lua_source): payload_bc = lua_source
    elif luac:             payload_bc = _compile(lua_source, luac, strip=True)
    else:                  payload_bc = lua_source

    # nonce + encrypt (seed = FNV(nonce_bytes) เมื่อ pkg='')
    nonce = struct.unpack(">I", os.urandom(4))[0] & 0xFFFFFFFF
    nonce_bytes = bytes([(nonce>>(8*i))&0xFF for i in range(4)])
    seed = _fnv32(nonce_bytes)
    enc = _lfsr_enc(payload_bc, seed)

    # Triple compile (all stripped)
    inner_src = _make_inner(enc, nonce, rng)
    loader_bc = _compile(inner_src, luac, strip=True) if luac else inner_src
    if not _is_bc(loader_bc): loader_bc = inner_src

    outer_src = _make_outer(loader_bc, rng)
    outer_bc  = _compile(outer_src, luac, strip=True) if luac else outer_src
    if not _is_bc(outer_bc): outer_bc = outer_src

    return _bootstrap(outer_bc).encode("utf-8")
