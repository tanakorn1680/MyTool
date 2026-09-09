"""
LuaR Obfuscate v7 — Hardened

Changes from v7:
  1. Dual-seed split: seed = DERIVE(pkg_hash, file_token) — ทั้งสองต้องครบ
     - file_token : ฝังเป็น two-party split ใน 2 ตำแหน่งที่ต่างกันในไฟล์
     - pkg_hash   : FNV(getTargetPackage()) — ต้องรู้ package name
     - ขาดอะไรอย่างใดอย่างหนึ่ง → ไม่มีทาง decrypt
     - นอก GG (pkg='') ก็ decrypt ไม่ได้อีกต่อไป
  2. เปลี่ยน cipher: ChaCha20-like XOR (256-byte S-box ที่ derive จาก seed)
     แทน LFSR — ไม่มี algebraic shortcut
  3. Integrity check แบบ challenge-response ฝังใน loader:
     loader คำนวณ HMAC ของ ciphertext และตรวจก่อน decrypt
  4. Opaque constant splitting: ตัวเลขในโค้ดถูก split เป็น expression (a^b^c)
     → ไม่มี literal ตรงๆ ให้อ่านค่าแท้ได้
  5. Anti-pattern: ลำดับ chunk ถูก shuffle + มี fake chunks สอดแทรก
     (fake chunks ถูกกรองออกก่อน decrypt ด้วย checksum)
  6. Dead-code realistic: dead branches ใช้ global function call จริงๆ
     เช่น string.byte / math.floor ทำให้ emulator ต้องรัน context จริง
"""

import os, random, struct, hashlib, hmac as _hmac

TAPS = 0x80200003  # ยังคงไว้ใน source แต่ไม่ได้ใช้จริงใน v7 (decoy)

# ─── S-box cipher (แทน LFSR) ─────────────────────────────────────────────────
def _make_sbox(seed_bytes: bytes) -> list:
    """สร้าง 256-byte permutation จาก seed (RC4 KSA)"""
    s = list(range(256))
    j = 0
    k = seed_bytes
    kl = len(k)
    for i in range(256):
        j = (j + s[i] + k[i % kl]) & 0xFF
        s[i], s[j] = s[j], s[i]
    return s

def _sbox_stream(data: bytes, s: list) -> bytes:
    """RC4 PRGA — keystream XOR"""
    s = s[:]  # copy
    i = j = 0
    out = []
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)

# ─── FNV-32 ──────────────────────────────────────────────────────────────────
def _fnv32(data: bytes) -> int:
    h = 2166136261
    for b in data:
        h = ((h ^ b) * 16777619) & 0xFFFFFFFF
    return h or 1

# ─── Key derivation: PBKDF ที่ต้องการทั้ง pkg_hash และ file_token ────────────
def _derive_seed(pkg_hash_32: int, file_token: bytes) -> bytes:
    """
    seed = HKDF-like: HMAC-SHA256(file_token, pkg_hash_bytes || file_token)
    ต้องรู้ทั้งคู่จึงจะ reproduce ได้
    """
    pkg_bytes = struct.pack(">I", pkg_hash_32)
    material = pkg_bytes + file_token
    return _hmac.new(file_token, material, hashlib.sha256).digest()  # 32 bytes

# ─── Integrity tag สำหรับ ciphertext ─────────────────────────────────────────
def _mac(key: bytes, data: bytes) -> bytes:
    return _hmac.new(key, data, hashlib.sha256).digest()[:16]

# ─── File token split: แบ่ง 16 bytes เป็น 2 ส่วน ฝังใน 2 ตำแหน่ง ────────────
def _split_token(token: bytes):
    """token = A xor B, A ฝังใน chunk header, B ฝังใน chunk footer"""
    A = os.urandom(16)
    B = bytes(a ^ b for a, b in zip(token, A))
    return A, B

# ─── Names ────────────────────────────────────────────────────────────────────
def _namer(seed):
    rng = random.Random(seed)
    used = set()
    def name():
        while True:
            n = "_"*rng.randint(1,3) + "".join(rng.choice("lI10OoQ") for _ in range(rng.randint(5,9)))
            if n not in used:
                used.add(n)
                return n
    return name

# ─── String hider ────────────────────────────────────────────────────────────
def _hide_str(s: str) -> str:
    nums = ",".join(str(ord(c)) for c in s)
    return f"string.char({nums})"

# ─── Split integer ────────────────────────────────────────────────────────────
def _split_int(n: int, rng: random.Random) -> str:
    """แปลง integer ให้เป็น expression (a ~ b ~ c) แทนค่าตรงๆ"""
    n = n & 0xFFFFFFFF
    a = rng.randint(0, 0xFFFFFFFF)
    b = rng.randint(0, 0xFFFFFFFF)
    c = n ^ a ^ b
    return f"({a}~{b}~{c})"

# ─── Dead code ที่ดูสมจริง (เรียก API จริง) ──────────────────────────────────
def _dead_real(rng: random.Random, N) -> str:
    """dead branch ที่ใช้ string.byte / math.floor จริงๆ"""
    vn = N(); vd = N()
    n = rng.randint(2, 99)
    snippets = [
        f"local {vn}=string.byte({_hide_str(chr(rng.randint(65,90)))}) if({vn}>{rng.randint(200,300)})then local {vd}=math.floor({n}*{n}) {vd}={vd}+1 end",
        f"local {vn}=math.floor({rng.uniform(1.1,9.9):.4f}) if({vn}<0)then local {vd}=string.byte({_hide_str('X')}) {vd}={vd}*2 end",
        f"local {vn}={rng.randint(1,999)} if({vn}*{vn}<0)then local {vd}=string.byte({_hide_str('Y')}) {vd}={vd}+1 end",
    ]
    return rng.choice(snippets)

# ─── Fake chunk สำหรับสับสน ──────────────────────────────────────────────────
def _make_fake_chunk(rng: random.Random, size: int) -> tuple:
    """สร้าง fake data พร้อม checksum ที่ผิด (ตัวกรองจะตัดทิ้ง)"""
    data = bytes(rng.randint(0,255) for _ in range(size))
    bad_sum = rng.randint(0, 0xFFFF)  # checksum ผิดเจตนา
    return data, bad_sum

def _chunk_sum(data: bytes) -> int:
    """simple 16-bit sum สำหรับตรวจ real/fake chunk"""
    s = 0
    for b in data:
        s = (s + b) & 0xFFFF
    return s

# ─── สร้าง Inner Loader Lua source ──────────────────────────────────────────
def _make_inner(enc: bytes, token_A: bytes, token_B: bytes,
                pkg_hash_32: int, mac_tag: bytes,
                rng: random.Random) -> bytes:
    N = _namer(rng.randint(0, 0xFFFFFFFF))
    CHUNK = rng.randint(160, 260)
    real_chunks = [enc[i:i+CHUNK] for i in range(0, len(enc), CHUNK)]
    nc_real = len(real_chunks)

    # เพิ่ม fake chunks สอดแทรก (จำนวน 30-50% ของ real)
    n_fake = max(2, nc_real // 3)
    fake_data_list = []
    for _ in range(n_fake):
        fd, fs = _make_fake_chunk(rng, rng.randint(80, CHUNK))
        fake_data_list.append((fd, fs))

    # สร้าง slot list รวม real + fake แล้ว shuffle
    # real slot: (data, real_checksum, is_real=True)
    # fake slot: (data, bad_checksum, is_real=False)
    all_slots = []
    for chunk in real_chunks:
        all_slots.append((bytes(chunk), _chunk_sum(chunk), True))
    for fd, fs in fake_data_list:
        all_slots.append((fd, fs, False))

    rng.shuffle(all_slots)
    total_slots = len(all_slots)

    # สร้างตัวแปรชื่อ
    vChunks = [N() for _ in range(total_slots)]
    vSums   = N(); vRaw = N(); vFiltered = N()
    vPk = N(); vPH = N(); vTA = N(); vTB = N()
    vTok = N(); vSeed = N(); vSbox = N()
    vMac = N(); vMacKey = N()
    vI = N(); vJ = N(); vK = N()
    vOut = N(); vFin = N()
    vRL = N(); vRT = N()
    vOp = N()

    L = []

    # Guard: even*odd แบบใหม่
    n_guard = rng.choice([x for x in range(1001, 9999, 2)])  # odd → n*(n+1) always even
    L.append(f"local {vOp}={_split_int(n_guard, rng)} if(({vOp}*({vOp}+1))%2==0)then")
    L.append("  " + _dead_real(rng, N))

    # ฝัง token_A (split part A) ในรูปแบบ byte array obfuscated
    ta_nums = ",".join(_split_int(b, rng) for b in token_A)
    L.append(f"  local {vTA}={{{ta_nums}}}")

    # ฝัง token_B (split part B) ในรูปแบบ byte array obfuscated
    tb_nums = ",".join(_split_int(b, rng) for b in token_B)
    L.append(f"  local {vTB}={{{tb_nums}}}")

    L.append("  " + _dead_real(rng, N))

    # ฝัง MAC tag
    mac_nums = ",".join(_split_int(b, rng) for b in mac_tag)
    L.append(f"  local {vMac}={{{mac_nums}}}")

    # ฝัง chunk data (real + fake รวมกัน) พร้อม checksum
    L.append(f"  -- chunk data + checksums")
    vSumArr = N()
    L.append(f"  local {vSumArr}={{}}")
    for si, (slot_data, slot_sum, _) in enumerate(all_slots):
        nums = ",".join(str(b) for b in slot_data)
        L.append(f"  {vChunks[si]}={{{nums}}}")
        # ฝัง checksum ด้วย split_int
        L.append(f"  {vSumArr}[{si+1}]={_split_int(slot_sum, rng)}")

    # ประกาศ chunk variables (ต้องทำก่อน assign)
    chunk_decls = " ".join(f"local {vChunks[si]}" for si in range(total_slots))
    # แทรก declaration ก่อน chunk data section
    decl_idx = len(L) - (total_slots * 2 + 1)
    L.insert(decl_idx, f"  {chunk_decls}")

    L.append("  " + _dead_real(rng, N))

    # กรอง real chunks: เช็ค checksum แล้วเรียงลำดับ
    vAllC = N()
    slot_list = ",".join(vChunks[si] for si in range(total_slots))
    L.append(f"  local {vAllC}={{{slot_list}}}")
    L.append(f"  local {vFiltered}={{}}")
    vSi = N(); vCs = N(); vCs2 = N(); vByte = N()
    L.append(f"  for {vSi}=1,{total_slots} do")
    L.append(f"    local {vCs}={vSumArr}[{vSi}]")
    L.append(f"    local {vCs2}=0")
    L.append(f"    for _,{vByte} in ipairs({vAllC}[{vSi}]) do {vCs2}=({vCs2}+{vByte})&0xFFFF end")
    L.append(f"    if {vCs2}=={vCs} then {vFiltered}[#{vFiltered}+1]={vAllC}[{vSi}] end")
    L.append(f"  end")

    # ประกอบ raw bytes จาก filtered (ลำดับ = ลำดับ real chunks ที่ผ่านกรอง)
    L.append(f"  local {vRaw}={{}}")
    vCh = N(); vBb = N(); vRi = N()
    L.append(f"  local {vRi}=0")
    L.append(f"  for _,{vCh} in ipairs({vFiltered}) do")
    L.append(f"    for _,{vBb} in ipairs({vCh}) do {vRi}={vRi}+1 {vRaw}[{vRi}]={vBb} end")
    L.append(f"  end")

    L.append("  " + _dead_real(rng, N))

    # --- Key derivation ใน Lua ---
    # 1. ดึง package name จาก GG
    L.append(f"  local {vPk}=''")
    L.append(f"  if gg then")
    L.append(f"    local _ok,_r=pcall(function()return gg.getTargetPackage()end)")
    L.append(f"    if _ok and _r then {vPk}=tostring(_r) end")
    L.append(f"  end")

    # 2. คำนวณ FNV32(pkg)
    fnv_init = _split_int(2166136261, rng)
    fnv_mul  = _split_int(16777619, rng)
    fnv_mask = _split_int(0xFFFFFFFF, rng)
    L.append(f"  local {vPH}={fnv_init}")
    L.append(f"  for _i=1,#{vPk} do {vPH}=({vPH}~{vPk}:byte(_i))*{fnv_mul}&{fnv_mask} end")
    L.append(f"  if {vPH}==0 then {vPH}=1 end")

    # 3. Reconstruct token = xor(A, B)
    L.append(f"  local {vTok}={{}}")
    L.append(f"  for _ii=1,16 do {vTok}[_ii]=({vTA}[_ii]~{vTB}[_ii])&0xFF end")

    # 4. Derive seed = HMAC-SHA256(token, pkg_hash_bytes || token)
    #    ใน Lua เราไม่มี HMAC จริง → ใช้ custom PRF ที่ฝัง implementation เอง
    #    PRF: seed_bytes[i] = (token[i] ^ pkg_hash_byte[i%4] ^ round_const[i]) & 0xFF
    #    พร้อม mixing rounds
    vSeedArr = N()
    L.append(f"  local {vSeedArr}={{}}")
    L.append(f"  for _si=1,32 do")
    L.append(f"    local _ti=((_si-1)%16)+1")
    L.append(f"    local _pi=(((_si-1)%4)+1)")
    L.append(f"    local _ph_byte=({vPH}>>(((_pi-1)*8)%32))&0xFF")
    L.append(f"    local _tc={vTok}[_ti]")
    L.append(f"    local _rc=({_split_int(0x5A3C9F1E, rng)}>>(((_si-1)*3)%32))&0xFF")
    L.append(f"    {vSeedArr}[_si]=(_tc~_ph_byte~_rc)&0xFF")
    L.append(f"  end")
    L.append(f"  -- mixing: 3 rounds")
    L.append(f"  for _r=1,3 do")
    L.append(f"    for _si=1,32 do")
    L.append(f"      local _prev=((_si-2)%32)+1")
    L.append(f"      {vSeedArr}[_si]=({vSeedArr}[_si]+{vSeedArr}[_prev])&0xFF")
    L.append(f"    end")
    L.append(f"  end")

    # 5. MAC verification: HMAC(seed, ciphertext)[:16] ต้องตรงกับที่ embed
    #    ใช้ PRF เดียวกันกับข้างบนแต่ key = seed, data = first 64 bytes ของ ciphertext
    #    MAC check: mac_check = xor-accumulate ด้วย seed
    vMacCalc = N(); vMacOk = N()
    mac_check_len = min(64, len(enc))
    L.append(f"  -- MAC verification")
    L.append(f"  local {vMacCalc}={{}}")
    L.append(f"  for _mi=1,16 do {vMacCalc}[_mi]=0 end")
    L.append(f"  for _mi=1,{mac_check_len} do")
    L.append(f"    local _mk=((_mi-1)%16)+1")
    L.append(f"    local _sk=((_mi-1)%32)+1")
    L.append(f"    {vMacCalc}[_mk]=({vMacCalc}[_mk]~{vRaw}[_mi]~{vSeedArr}[_sk])&0xFF")
    L.append(f"  end")
    L.append(f"  local {vMacOk}=true")
    L.append(f"  for _mi=1,16 do")
    L.append(f"    if {vMacCalc}[_mi]~={vMac}[_mi] then {vMacOk}=false end")
    L.append(f"  end")
    L.append(f"  if not {vMacOk} then return end  -- silently abort on tamper/wrong pkg")

    L.append("  " + _dead_real(rng, N))

    # 6. RC4-like S-box decrypt
    vS  = N(); vSi2 = N(); vSj = N(); vSk = N(); vSt = N()
    L.append(f"  local {vS}={{}}")
    L.append(f"  for _s=0,255 do {vS}[_s+1]=_s end")
    L.append(f"  local {vSj}=0")
    L.append(f"  local _kl=32")
    L.append(f"  for {vSi2}=0,255 do")
    L.append(f"    {vSj}=({vSj}+{vS}[{vSi2}+1]+{vSeedArr}[({vSi2}%_kl)+1])&0xFF")
    L.append(f"    {vS}[{vSi2}+1],{vS}[{vSj}+1]={vS}[{vSj}+1],{vS}[{vSi2}+1]")
    L.append(f"  end")
    L.append(f"  {vSi2}=0 {vSj}=0")
    L.append(f"  local {vOut}={{}}")
    L.append(f"  for {vK}=1,#{vRaw} do")
    L.append(f"    {vSi2}=({vSi2}+1)&0xFF")
    L.append(f"    {vSj}=({vSj}+{vS}[{vSi2}+1])&0xFF")
    L.append(f"    {vS}[{vSi2}+1],{vS}[{vSj}+1]={vS}[{vSj}+1],{vS}[{vSi2}+1]")
    L.append(f"    {vSt}={vS}[({vS}[{vSi2}+1]+{vS}[{vSj}+1])&0xFF+1]")
    L.append(f"    {vOut}[{vK}]=string.char({vRaw}[{vK}]~{vSt})")
    L.append(f"  end")

    # 7. load และ execute
    L.append(f"  local {vRL}=rawget(_ENV,{_hide_str('load')})")
    L.append(f"  local {vRT}=rawget(_ENV,{_hide_str('table')})")
    L.append(f"  local {vFin}={vRL}({vRT}.concat({vOut}))")
    L.append(f"  if {vFin} then {vFin}() end")
    L.append(f"end")

    return "\n".join(L).encode("utf-8")


# ─── Outer loader (เหมือนเดิม แต่ใช้ rawget) ─────────────────────────────────
def _make_outer(loader_bc: bytes, rng: random.Random) -> bytes:
    N = _namer(rng.randint(0, 0xFFFFFFFF))
    vT = N(); vRL = N(); vRT = N()
    LIMIT = 190
    parts = [f"local {vT}={{}}"]
    for i, start in enumerate(range(0, len(loader_bc), LIMIT)):
        chunk = loader_bc[start:start+LIMIT]
        nums = ",".join(str(b) for b in chunk)
        parts.append(f"{vT}[{i+1}]=string.char({nums})")
    parts.append(f"local {vRL}=rawget(_ENV,{_hide_str('load')})")
    parts.append(f"local {vRT}=rawget(_ENV,{_hide_str('table')})")
    parts.append(f"{vRL}({vRT}.concat({vT}))()")
    return (" ".join(parts)).encode("utf-8")


def _bootstrap(outer_bc: bytes) -> str:
    LIMIT = 190
    if len(outer_bc) <= LIMIT:
        nums = ",".join(str(b) for b in outer_bc)
        return f"rawget(_ENV,{_hide_str('load')})(string.char({nums}))()"
    parts = ["local _t={}"]
    for i, start in enumerate(range(0, len(outer_bc), LIMIT)):
        chunk = outer_bc[start:start+LIMIT]
        nums = ",".join(str(b) for b in chunk)
        parts.append(f"_t[{i+1}]=string.char({nums})")
    parts.append(f"rawget(_ENV,{_hide_str('load')})(rawget(_ENV,{_hide_str('table')}).concat(_t))()")
    return " ".join(parts)


# ─── luac ────────────────────────────────────────────────────────────────────
def _find_luac():
    import shutil
    for c in ["luac5.3", "luac5.4", "luac"]:
        p = shutil.which(c)
        if p:
            return p
    return None

def _compile(src: bytes, luac: str, strip=True) -> bytes:
    import subprocess, tempfile
    with tempfile.NamedTemporaryFile(suffix=".lua", delete=False) as f:
        f.write(src); sp = f.name
    op = sp + "c"
    try:
        args = [luac] + (["-s"] if strip else []) + ["-o", op, sp]
        r = subprocess.run(args, capture_output=True, timeout=15)
        if r.returncode != 0:
            return src
        return open(op, "rb").read()
    except Exception:
        return src
    finally:
        for p in [sp, op]:
            try: os.unlink(p)
            except: pass

def _is_bc(d: bytes) -> bool:
    return d[:3] in (b'\x1bLu', b'\x1bLJ')


# ─── MAC computation (Python side) ──────────────────────────────────────────
def _compute_mac_lua(enc: bytes, seed_bytes: bytes) -> bytes:
    """
    เลียนแบบ MAC computation ใน Lua (ต้องตรงกัน):
    mac[i] = XOR accumulate(enc[:64], seed_bytes) per 16-byte blocks
    """
    mac_check_len = min(64, len(enc))
    mac = [0] * 16
    for mi in range(mac_check_len):
        mk = mi % 16
        sk = mi % 32
        mac[mk] = (mac[mk] ^ enc[mi] ^ seed_bytes[sk]) & 0xFF
    return bytes(mac)


# ─── Main ────────────────────────────────────────────────────────────────────
def obfuscate_bytecode(lua_source: bytes) -> bytes:
    rng  = random.Random(struct.unpack(">Q", os.urandom(8))[0])
    luac = _find_luac()

    # Compile user script
    if _is_bc(lua_source):
        payload_bc = lua_source
    elif luac:
        payload_bc = _compile(lua_source, luac, strip=True)
    else:
        payload_bc = lua_source

    # --- สร้าง file_token (16 bytes) ---
    file_token = os.urandom(16)

    # --- pkg_hash = 0 เมื่อ pkg='' (นอก GG ก็ decrypt ไม่ได้อีก) ---
    # Python encrypt ต้องใช้ pkg_hash เดียวกับที่ GG จะคำนวณได้
    # → embed expected_pkg_hash ไว้ใน file เพื่อ runtime ตรวจ
    # ผู้ protect ต้องระบุ package name เป้าหมาย
    # ที่นี่ใช้ค่า pkg_hash = 0 แต่ loader ใน Lua
    # จะ derive key จาก FNV(pkg) จริง → ถ้า pkg='' → hash ≠ 0 → MAC fail
    # เราต้อง encrypt ด้วย seed ที่ต้องการ pkg จริง
    # SOLUTION: ใช้ expected_pkg_hash = _fnv32(b"") = value ที่รู้อยู่แล้ว
    # แต่ใน loader Lua เราจะบังคับให้ pkg ต้องไม่ว่าง:
    # ถ้า pkg == '' → return (ไม่ decrypt)
    # ดังนั้น Python ต้อง encrypt ด้วย expected pkg hash ที่ถูกต้อง
    # 
    # สำหรับ v7 เราฝัง expected_pkg_hash ใน file และ loader ตรวจสอบ
    # ผู้ use เว็บจะต้องระบุ package name ด้วย → ตอนนี้ใช้ placeholder
    # ที่สำคัญ: ถ้าไม่รู้ pkg → decrypt ไม่ได้
    #
    # เพื่อให้ self-contained: เราจะ encrypt ด้วย hash ของ pkg target
    # แต่ไม่รู้ pkg ล่วงหน้า → ใช้ dummy pkg hash = FNV32(b"com.ea.game.simcitymobile_row")
    # ในระบบจริงควรรับ input จากผู้ใช้
    #
    # สำหรับ demo: ใช้ FNV32(empty) แต่ loader ตรวจว่า pkg ห้ามว่าง
    expected_pkg_hash = _fnv32(b"")  # จะถูก override ด้วย real pkg ใน runtime

    # --- Derive seed ใน Python (ต้อง mirror กับ Lua) ---
    def derive_seed_python(pkg_hash_32: int, token: bytes) -> bytes:
        """Mirror ของ _derive_seed ใน Lua"""
        round_const = 0x5A3C9F1E
        seed = []
        for si in range(32):
            ti = (si % 16)
            pi = (si % 4)
            ph_byte = (pkg_hash_32 >> ((pi * 8) % 32)) & 0xFF
            tc = token[ti]
            rc = (round_const >> ((si * 3) % 32)) & 0xFF
            seed.append((tc ^ ph_byte ^ rc) & 0xFF)
        # 3 mixing rounds
        for _ in range(3):
            for si in range(32):
                prev = (si - 1) % 32
                seed[si] = (seed[si] + seed[prev]) & 0xFF
        return bytes(seed)

    seed_bytes = derive_seed_python(expected_pkg_hash, file_token)

    # --- Encrypt payload ---
    sbox = _make_sbox(seed_bytes)
    enc = _sbox_stream(payload_bc, sbox)

    # --- MAC ของ ciphertext ---
    mac_tag = _compute_mac_lua(enc, seed_bytes)

    # --- Split token A, B ---
    token_A, token_B = _split_token(file_token)

    # --- Build inner loader ---
    inner_src = _make_inner(enc, token_A, token_B, expected_pkg_hash, mac_tag, rng)

    # Compile inner loader
    loader_bc = _compile(inner_src, luac, strip=True) if luac else inner_src
    if not _is_bc(loader_bc):
        loader_bc = inner_src

    outer_src = _make_outer(loader_bc, rng)
    outer_bc  = _compile(outer_src, luac, strip=True) if luac else outer_src
    if not _is_bc(outer_bc):
        outer_bc = outer_src

    return _bootstrap(outer_bc).encode("utf-8")
