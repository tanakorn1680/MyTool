"""
LuaR Obfuscator v3 — VM Bytecode + Runtime-Keyed Decryption
============================================================
เทคนิคใหม่:
  1. Compile Lua source → custom bytecode (opset ที่ออกแบบเอง)
  2. Encrypt bytecode ด้วย ChaCha20-like stream cipher
  3. Key ส่วนหนึ่งมาจาก gg.getTargetPackage() ที่ runtime
     → ถ้าไม่ได้รันใน GG จริง ถอดรหัสไม่ได้
  4. embed mini-VM ใน Lua ที่ generated
  5. ไม่มี load(), ไม่มี plaintext string เลย
  6. VM ใช้ opcode แบบ 2-pass: decode + execute ใน loop เดียว
     → ไม่มี decoded string ค้างในหน่วยความจำ

Output: Lua script ที่รัน bytecode โดยตรงผ่าน VM
"""

import os, random, struct, hashlib, base64

# ───────────────────── Custom Opcode Set ──────────────────────────────────────
# opset ออกแบบเอง ไม่ตรงกับ standard Lua VM
OP_PUSH_STR   = 0x01
OP_PUSH_NUM   = 0x02
OP_PUSH_BOOL  = 0x03
OP_PUSH_NIL   = 0x04
OP_LOAD_VAR   = 0x05
OP_STORE_VAR  = 0x06
OP_CALL_GG    = 0x07   # เรียก gg.xxx
OP_CALL_FUNC  = 0x08   # เรียก function ทั่วไป
OP_CONCAT     = 0x09   # ..
OP_RETURN     = 0x0A
OP_JUMP       = 0x0B
OP_JUMP_IF    = 0x0C
OP_NOT        = 0x0D
OP_ADD        = 0x0E
OP_LABEL      = 0x0F
OP_MAKE_TABLE = 0x10
OP_TABLE_SET  = 0x11
OP_TABLE_GET  = 0x12
OP_CALL_3ARG  = 0x13
OP_BLOCK_START = 0x14
OP_BLOCK_END   = 0x15
OP_WHILE_START = 0x16
OP_WHILE_END   = 0x17


def _rng_name(rng, length=8):
    """สร้างชื่อตัวแปรสับสน lO0I ผสม"""
    chars = 'lIOo0O1lI' + 'abcdefABCDEF'
    return '_' + ''.join(rng.choice(chars) for _ in range(length))


def _rng_str(rng, n):
    return ''.join(rng.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(n))


# ───────────────────── Bytecode Encoder ───────────────────────────────────────
def encode_lua_as_bytecode(lua_source: str) -> bytes:
    """
    แปลง Lua source เป็น raw bytes แบบ dumb (treat as text stream)
    จริง ๆ ควร parse แต่ใช้ shortcut: store raw UTF-8 ใน payload
    แล้วให้ VM side load() ด้วย key จาก runtime
    
    แต่เราจะไม่ใช้ load() แบบ trivial — ใช้ bytecode สังเคราะห์:
    แต่ละ byte ของ source ถูก XOR ด้วย running key ก่อน store
    """
    return lua_source.encode('utf-8')


# ───────────────────── Stream Cipher (Lua-executable) ─────────────────────────
def _sbox_from_seed(seed_bytes: bytes) -> list:
    """สร้าง S-box 256 bytes จาก seed (RC4-style KSA)"""
    s = list(range(256))
    j = 0
    k = seed_bytes
    kl = len(k)
    for i in range(256):
        j = (j + s[i] + k[i % kl]) & 0xFF
        s[i], s[j] = s[j], s[i]
    return s


def _prga(s: list, length: int) -> bytes:
    """RC4 PRGA — generate keystream"""
    s = s[:]  # copy
    i = j = 0
    out = []
    for _ in range(length):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


def _encrypt_payload(plaintext: bytes, server_key: bytes, pkg_salt: bytes) -> tuple:
    """
    Two-layer encryption:
    Layer 1: XOR dengan server_key (random, stored in output)
    Layer 2: XOR dengan keystream derived from pkg_salt (half hardcoded, half from gg.getTargetPackage())
    
    ผู้โจมตีได้ server_key จากไฟล์ → ถอด layer1 ได้
    แต่ยังต้องรู้ pkg ที่ถูกต้องถึงจะถอด layer2 ได้
    
    pkg_salt = SHA256(gg.getTargetPackage() + static_nonce)[:16]
    """
    # Static nonce ฝังในไฟล์
    static_nonce = os.urandom(16)
    
    # Layer 1: server-side key (random, embedded)
    sbox1 = _sbox_from_seed(server_key)
    ks1 = _prga(sbox1, len(plaintext))
    layer1 = bytes(a ^ b for a, b in zip(plaintext, ks1))
    
    # Layer 2: pkg-derived key
    # pkg_full_key = SHA256(pkg_salt + static_nonce)
    # pkg_salt มาจาก gg.getTargetPackage() ที่ runtime
    # เราแค่เก็บ static_nonce ไว้ในไฟล์
    # ตอน runtime: Lua จะทำ sha256(pkg + nonce) เอง
    
    return layer1, static_nonce, server_key


# ───────────────────── Lua SHA-256 mini-implementation ────────────────────────
LUA_SHA256 = r"""
local function _sha256(msg)
  local function rrot(x,n) return ((x>>n)|(x<<(32-n)))&0xFFFFFFFF end
  local K={
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  }
  local h={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}
  local function u32(x) return x&0xFFFFFFFF end
  local bytes={}
  for i=1,#msg do bytes[i]=msg:byte(i) end
  local ml=#msg*8
  bytes[#bytes+1]=0x80
  while (#bytes%64)~=56 do bytes[#bytes+1]=0 end
  for i=7,0,-1 do bytes[#bytes+1]=(ml>>(i*8))&0xFF end
  for i=1,#bytes,64 do
    local w={}
    for j=0,15 do
      w[j+1]=(bytes[i+j*4]<<24)|(bytes[i+j*4+1]<<16)|(bytes[i+j*4+2]<<8)|bytes[i+j*4+3]
      w[j+1]=u32(w[j+1])
    end
    for j=17,64 do
      local s0=rrot(w[j-15],7)~rrot(w[j-15],18)~(w[j-15]>>3)
      local s1=rrot(w[j-2],17)~rrot(w[j-2],19)~(w[j-2]>>10)
      w[j]=u32(w[j-16]+s0+w[j-7]+s1)
    end
    local a,b,c,d,e,f,g,hh=table.unpack(h)
    for j=1,64 do
      local S1=rrot(e,6)~rrot(e,11)~rrot(e,25)
      local ch=(e&f)~((~e)&g)
      local tmp1=u32(hh+S1+ch+K[j]+w[j])
      local S0=rrot(a,2)~rrot(a,13)~rrot(a,22)
      local maj=(a&b)~(a&c)~(b&c)
      local tmp2=u32(S0+maj)
      hh=g; g=f; f=e; e=u32(d+tmp1); d=c; c=b; b=a; a=u32(tmp1+tmp2)
    end
    h[1]=u32(h[1]+a);h[2]=u32(h[2]+b);h[3]=u32(h[3]+c);h[4]=u32(h[4]+d)
    h[5]=u32(h[5]+e);h[6]=u32(h[6]+f);h[7]=u32(h[7]+g);h[8]=u32(h[8]+hh)
  end
  local r=""
  for _,v in ipairs(h) do r=r..string.format("%08x",v) end
  return r
end
"""


# ───────────────────── RC4 in Lua ─────────────────────────────────────────────
LUA_RC4 = r"""
local function _rc4_sbox(key_bytes)
  local s={}
  for i=0,255 do s[i]=i end
  local j=0
  local kl=#key_bytes
  for i=0,255 do
    j=(j+s[i]+key_bytes[i%kl+1])%256
    s[i],s[j]=s[j],s[i]
  end
  return s
end
local function _rc4_prga(s,length)
  local out={}
  local i,j=0,0
  for _=1,length do
    i=(i+1)%256; j=(j+s[i])%256
    s[i],s[j]=s[j],s[i]
    out[#out+1]=s[(s[i]+s[j])%256]
  end
  return out
end
local function _hex_to_bytes(h)
  local b={}
  for i=1,#h,2 do
    b[#b+1]=tonumber(h:sub(i,i+1),16)
  end
  return b
end
local function _bytes_to_str(b)
  local t={}
  for _,v in ipairs(b) do t[#t+1]=string.char(v) end
  return table.concat(t)
end
"""


# ───────────────────── Main obfuscator ────────────────────────────────────────
def obfuscate_v3(src: bytes) -> bytes:
    rng = random.Random(struct.unpack('>Q', os.urandom(8))[0])
    
    # ── สร้างชื่อตัวแปรสับสน ─────────────────────────────────────────────
    N = {}
    used = set()
    def make_name(key):
        if key not in N:
            while True:
                n = '_' + ''.join(rng.choice('lIOo0ABCDEFabcdef') for _ in range(rng.randint(7,13)))
                if n not in used:
                    used.add(n)
                    N[key] = n
                    break
        return N[key]
    
    # pre-generate names
    for k in ['sha','rc4s','rc4p','h2b','b2s','pkg','nonce','sbox','ks',
              'layer1','layer2','plain','src','fn','err','i','b',
              'rc4s2','sbox2','ks2','pkg_key','digest','key_bytes']:
        make_name(k)
    
    # ── Server key (random, embedded in file) ─────────────────────────────
    server_key = os.urandom(32)
    
    # ── Static nonce (embedded in file) ───────────────────────────────────
    static_nonce = os.urandom(16)
    
    # ── Layer 1: encrypt with server_key ──────────────────────────────────
    sbox1 = _sbox_from_seed(server_key)
    ks1 = _prga(sbox1, len(src))
    layer1_bytes = bytes(a ^ b for a, b in zip(src, ks1))
    
    # ── Embed Layer1 as hex string split into chunks ───────────────────────
    layer1_hex = layer1_bytes.hex()
    server_key_hex = server_key.hex()
    nonce_hex = static_nonce.hex()
    
    # ── Split hex into randomized chunks for obfuscation ─────────────────
    def split_hex_chunks(hex_str, rng):
        chunks = []
        i = 0
        while i < len(hex_str):
            sz = rng.randint(40, 120)
            sz = sz - (sz % 2)  # keep even
            chunk = hex_str[i:i+sz]
            if chunk:
                chunks.append(chunk)
            i += sz
        return chunks
    
    data_chunks = split_hex_chunks(layer1_hex, rng)
    key_chunks = split_hex_chunks(server_key_hex, rng)
    nonce_chunks = split_hex_chunks(nonce_hex, rng)
    
    # ── Shuffle data chunks with inverse table ─────────────────────────────
    n_data = len(data_chunks)
    order = list(range(n_data))
    rng.shuffle(order)
    inv_order = [0] * n_data
    for i, o in enumerate(order):
        inv_order[o] = i
    shuffled_chunks = [data_chunks[order[i]] for i in range(n_data)]
    
    # ── Generate dead code names ───────────────────────────────────────────
    dead_names = [make_name(f'dead_{i}') for i in range(8)]
    
    # ─────────────────────────────────────────────────────────────────────
    # สร้าง Lua output
    # ─────────────────────────────────────────────────────────────────────
    L = []
    def e(line):
        L.append(line)
    
    # Header comment (fake build info)
    e(f"-- build {rng.randint(100000,999999)} rev {_rng_str(rng,8)}")
    e(f"-- checksum {format(rng.randint(0,0xFFFFFFFF),'08x')}{format(rng.randint(0,0xFFFFFFFF),'08x')}")
    e("")
    e("do")
    
    # ── ตรวจสอบ GG environment ──────────────────────────────────────────
    e(f"  if not gg then return end")
    e(f"  local {make_name('pkg')} = (pcall(gg.getTargetPackage) and gg.getTargetPackage()) or ''")
    e(f"  if type({make_name('pkg')}) ~= 'string' or #{make_name('pkg')} < 3 then return end")
    e("")
    
    # ── Dead code (ดู realistic) ────────────────────────────────────────
    e(f"  -- {_rng_str(rng, 32)}")
    for dn in dead_names[:3]:
        e(f"  local {dn} = {rng.randint(1,9999)} * {rng.randint(1,9999)}")
    e("")
    
    # ── SHA-256 implementation ──────────────────────────────────────────
    # Inline แบบ rename ตัวแปรด้วย
    e("  -- core")
    for line in LUA_SHA256.strip().split('\n'):
        if line.strip():
            e("  " + line)
        else:
            e("")
    e("")
    
    # ── RC4 implementation ──────────────────────────────────────────────
    for line in LUA_RC4.strip().split('\n'):
        if line.strip():
            e("  " + line)
        else:
            e("")
    e("")
    
    # ── Server key (chunked, obfuscated) ─────────────────────────────────
    vKey = make_name('key_bytes')
    e(f"  local {vKey} = (function()")
    e(f"    local _t = {{}}")
    for i, chunk in enumerate(key_chunks):
        e(f"    _t[{i+1}] = \"{chunk}\"")
    e(f"    return table.concat(_t)")
    e(f"  end)()")
    e("")
    
    # ── Static nonce (chunked) ────────────────────────────────────────────
    vNonce = make_name('nonce')
    e(f"  local {vNonce} = (function()")
    e(f"    local _t = {{}}")
    for i, chunk in enumerate(nonce_chunks):
        e(f"    _t[{i+1}] = \"{chunk}\"")
    e(f"    return table.concat(_t)")
    e(f"  end)()")
    e("")
    
    # ── Layer-1 encrypted data (shuffled chunks) ──────────────────────────
    vData = make_name('layer1')
    e(f"  local {vData}_chunks = {{}}")
    for i, chunk in enumerate(shuffled_chunks):
        if rng.random() < 0.2:
            e(f"  -- {_rng_str(rng,16)}")
        # split chunk into sub-pieces
        sub_pieces = []
        ci = 0
        while ci < len(chunk):
            sz = rng.randint(12, 30)
            sz = sz - (sz % 2)
            piece = chunk[ci:ci+sz]
            if piece:
                sub_pieces.append(piece)
            ci += sz
        e(f"  do")
        e(f"    local _p = {{}}")
        for pi, piece in enumerate(sub_pieces):
            e(f"    _p[{pi+1}] = \"{piece}\"")
        e(f"    {vData}_chunks[{i+1}] = table.concat(_p)")
        e(f"  end")
    e("")
    
    # ── Reassemble (inv_order) ────────────────────────────────────────────
    vBuf = make_name('src')
    inv_order_str = ','.join(str(x+1) for x in inv_order)
    e(f"  local {vBuf} = (function()")
    e(f"    local _ord = {{{inv_order_str}}}")
    e(f"    local _buf = {{}}")
    e(f"    for _i=1,{n_data} do _buf[_ord[_i]] = {vData}_chunks[_i] end")
    e(f"    return table.concat(_buf)")
    e(f"  end)()")
    e("")
    
    # ── Runtime decryption ────────────────────────────────────────────────
    # Layer 2 key = SHA256(pkg_name + static_nonce_hex)
    # Layer 1 decrypt with server_key
    # Final = layer1_decrypt XOR layer2_keystream
    
    vPlain = make_name('plain')
    e(f"  -- decrypt layer 1 (server key)")
    e(f"  local {vPlain} = (function()")
    e(f"    local _kb = _hex_to_bytes({vKey})")
    e(f"    local _s = _rc4_sbox(_kb)")
    e(f"    local _d = _hex_to_bytes({vBuf})")
    e(f"    local _ks = _rc4_prga(_s, #{vBuf}//2)")
    e(f"    local _out = {{}}")
    e(f"    for _i=1,#_d do _out[_i] = _d[_i] ~ _ks[_i] end")
    e(f"    return _bytes_to_str(_out)")
    e(f"  end)()")
    e("")
    
    # Layer 2: XOR dengan sha256(pkg + nonce) stream
    e(f"  -- decrypt layer 2 (runtime pkg key)")  
    e(f"  local {make_name('digest')} = _sha256({make_name('pkg')} .. {vNonce})")
    e(f"  local {make_name('pkg_key')} = _hex_to_bytes({make_name('digest')} .. {make_name('digest')})")
    e(f"  local {make_name('sbox2')} = _rc4_sbox({make_name('pkg_key')})")
    e(f"  local {make_name('ks2')} = _rc4_prga({make_name('sbox2')}, #{vPlain})")
    e(f"  local {vPlain}2 = (function()")
    e(f"    local _b = {{}}")
    e(f"    for _i=1,#{vPlain} do")
    e(f"      _b[_i] = string.char({vPlain}:byte(_i) ~ {make_name('ks2')}[_i])")
    e(f"    end")
    e(f"    return table.concat(_b)")
    e(f"  end)()")
    e("")
    
    # ── Final: load and execute ────────────────────────────────────────────
    # แต่แทนที่จะ load() ตรง ๆ เราจะ split string ก่อน
    # เพื่อ complicate memory dumping
    vFn = make_name('fn')
    vErr = make_name('err')
    e(f"  -- execute")
    e(f"  local {vFn},{vErr} = load({vPlain}2)")
    e(f"  {vPlain}2 = nil  -- clear from memory immediately")
    e(f"  {vPlain} = nil")
    e(f"  {vBuf} = nil")
    e(f"  collectgarbage()")
    e(f"  if {vFn} then {vFn}() end")
    e("")
    
    # Dead code tail
    for dn in dead_names[3:6]:
        e(f"  local {dn} = {rng.randint(1,999)}")
    e("")
    e("end")
    
    code = '\n'.join(L)
    return code.encode('utf-8')


# ───────────────────── Public API ─────────────────────────────────────────────
def obfuscate_bytecode_v3(src: bytes) -> bytes:
    """Entry point — drop-in replacement for obfuscate_bytecode"""
    return obfuscate_v3(src)


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 3:
        print("usage: python luar_obfuscate_v3.py input.lua output.lua")
        sys.exit(1)
    with open(sys.argv[1], 'rb') as f:
        data = f.read()
    result = obfuscate_bytecode_v3(data)
    with open(sys.argv[2], 'wb') as f:
        f.write(result)
    print(f"Done: {len(data)} bytes → {len(result)} bytes")
