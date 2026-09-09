"""
LuaR Runtime — stack-based interpreter for the internal IR.
"""

import json
import math
import sys

from luar_compiler import decompile_payload, Op


class LuaRuntimeError(Exception):
    pass


class LuaTable:
    """Minimal Lua-like table."""
    def __init__(self):
        self.data = {}

    def rawget(self, key):
        return self.data.get(key)

    def rawset(self, key, value):
        self.data[key] = value

    def __repr__(self):
        return f"table({self.data})"

    def __len__(self):
        # Sequence length: consecutive integer keys from 1
        n = 0
        while (n + 1) in self.data:
            n += 1
        return n


class LuaClosure:
    def __init__(self, params, instructions, constants, upvalues=None):
        self.params = params
        self.instructions = instructions
        self.constants = constants
        self.upvalues = upvalues or {}

    def __repr__(self):
        return f"<function ({', '.join(self.params)})>"


def _tostring(v):
    if v is None:
        return "nil"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float) and v == int(v):
        return str(int(v))
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, LuaTable):
        return "table: 0x" + format(id(v), "x")
    if isinstance(v, LuaClosure):
        return "function: 0x" + format(id(v), "x")
    return str(v)


def _tonumber(v):
    if isinstance(v, (int, float)):
        return v
    try:
        return int(v)
    except (ValueError, TypeError):
        pass
    try:
        return float(v)
    except (ValueError, TypeError):
        return None


def _lua_equal(a, b):
    if type(a) != type(b):
        return False
    return a == b


# ─────────────────────────── VM ─────────────────────────────────────────────

class VM:
    def __init__(self, globals_=None):
        self.globals = globals_ if globals_ is not None else self._default_globals()

    def _default_globals(self):
        g = {}

        def lua_print(*args):
            print("\t".join(_tostring(a) for a in args))

        def lua_tostring(v, *_):
            return _tostring(v)

        def lua_tonumber(v, *_):
            return _tonumber(v)

        def lua_type(v, *_):
            if v is None:
                return "nil"
            if isinstance(v, bool):
                return "boolean"
            if isinstance(v, (int, float)):
                return "number"
            if isinstance(v, str):
                return "string"
            if isinstance(v, LuaTable):
                return "table"
            if isinstance(v, LuaClosure):
                return "function"
            return "userdata"

        def lua_ipairs(t, *_):
            i = [0]
            def _iter(*_):
                i[0] += 1
                v = t.rawget(i[0])
                if v is None:
                    return None
                tbl = LuaTable()
                tbl.rawset(1, i[0])
                tbl.rawset(2, v)
                return tbl
            return LuaClosure([], [], [], {})  # stub — not fully iterable in MVP

        def lua_pairs(t, *_):
            items = list(t.data.items())
            idx = [0]
            def _next(*_):
                if idx[0] >= len(items):
                    return None
                k, v = items[idx[0]]
                idx[0] += 1
                tbl = LuaTable()
                tbl.rawset(1, k)
                tbl.rawset(2, v)
                return tbl
            return LuaClosure([], [], [], {})

        def lua_error(msg, *_):
            raise LuaRuntimeError(str(msg))

        def lua_assert(v, msg=None, *_):
            if not v:
                raise LuaRuntimeError(str(msg) if msg else "assertion failed")
            return v

        def lua_pcall(f, *args):
            try:
                result = self.call(f, list(args))
                return True, result
            except Exception as e:
                return False, str(e)

        def lua_unpack(t, *_):
            # return first value (MVP)
            return t.rawget(1)

        def lua_select(idx, *args):
            if idx == "#":
                return len(args)
            return args[int(idx)-1] if int(idx) <= len(args) else None

        def lua_rawget(t, k, *_):
            return t.rawget(k)

        def lua_rawset(t, k, v, *_):
            t.rawset(k, v)
            return t

        def lua_setmetatable(t, mt, *_):
            t._meta = mt
            return t

        def lua_getmetatable(t, *_):
            return getattr(t, "_meta", None)

        # string library
        string_lib = LuaTable()
        def str_format(fmt, *args):
            # basic %s %d %f support
            result = ""
            arg_idx = [0]
            i = 0
            while i < len(fmt):
                if fmt[i] == "%" and i+1 < len(fmt):
                    spec = fmt[i+1]
                    a = args[arg_idx[0]] if arg_idx[0] < len(args) else None
                    arg_idx[0] += 1
                    if spec == "s":
                        result += _tostring(a)
                    elif spec == "d" or spec == "i":
                        result += str(int(a) if a is not None else 0)
                    elif spec == "f":
                        result += f"{float(a):.6f}" if a is not None else "0.000000"
                    elif spec == "g":
                        result += f"{float(a):g}" if a is not None else "0"
                    elif spec == "%":
                        result += "%"
                        arg_idx[0] -= 1
                    else:
                        result += "%" + spec
                    i += 2
                else:
                    result += fmt[i]
                    i += 1
            return result

        def str_len(s, *_):
            return len(str(s))

        def str_sub(s, i, j=None, *_):
            s = str(s)
            i = int(i)
            if i < 0: i = max(0, len(s) + i + 1)
            elif i > 0: i -= 1
            if j is None:
                return s[i:]
            j = int(j)
            if j < 0: j = len(s) + j + 1
            return s[i:j]

        def str_rep(s, n, *_):
            return str(s) * int(n)

        def str_upper(s, *_): return str(s).upper()
        def str_lower(s, *_): return str(s).lower()
        def str_find(s, pat, *_):
            idx = str(s).find(str(pat))
            if idx < 0: return None
            return idx + 1

        for name, fn in [
            ("format", str_format), ("len", str_len), ("sub", str_sub),
            ("rep", str_rep), ("upper", str_upper), ("lower", str_lower),
            ("find", str_find),
        ]:
            string_lib.rawset(name, self._wrap_builtin(name, fn))

        # math library
        math_lib = LuaTable()
        for name in ["floor","ceil","sqrt","sin","cos","tan","exp","log",
                     "max","min","pi","huge"]:
            val = getattr(math, name, None)
            if callable(val):
                math_lib.rawset(name, self._wrap_builtin("math."+ name, val))
            elif val is not None:
                math_lib.rawset(name, val)

        math_lib.rawset("abs", self._wrap_builtin("math.abs", lambda a, *_: abs(a)))

        def math_pow(a, b, *_): return float(a) ** float(b)
        def math_random(*args):
            import random
            if not args: return random.random()
            if len(args) == 1: return random.randint(1, int(args[0]))
            return random.randint(int(args[0]), int(args[1]))
        def math_randomseed(n, *_):
            import random; random.seed(n)

        for name, fn in [("pow", math_pow), ("random", math_random),
                         ("randomseed", math_randomseed), ("fmod", math.fmod)]:
            math_lib.rawset(name, self._wrap_builtin("math."+name, fn))
        math_lib.rawset("pi", math.pi)
        math_lib.rawset("huge", math.inf)
        math_lib.rawset("maxinteger", 2**53)

        # os library (minimal)
        os_lib = LuaTable()
        import time as _time
        os_lib.rawset("time", self._wrap_builtin("os.time", lambda *_: int(_time.time())))
        os_lib.rawset("clock", self._wrap_builtin("os.clock", lambda *_: _time.process_time()))
        os_lib.rawset("exit", self._wrap_builtin("os.exit", lambda code=0, *_: sys.exit(int(code) if code is not None else 0)))

        # table library
        table_lib = LuaTable()
        def tbl_insert(t, pos_or_val, val=None, *_):
            if val is None:
                n = len(t) + 1
                t.rawset(n, pos_or_val)
            else:
                n = int(pos_or_val)
                t.rawset(n, val)
        def tbl_remove(t, pos=None, *_):
            n = len(t)
            if pos is None: pos = n
            val = t.rawget(int(pos))
            for i in range(int(pos), n):
                t.rawset(i, t.rawget(i+1))
            t.rawset(n, None)
            return val
        def tbl_concat(t, sep="", *_):
            parts = []
            i = 1
            while True:
                v = t.rawget(i)
                if v is None: break
                parts.append(_tostring(v))
                i += 1
            return str(sep).join(parts)

        for name, fn in [("insert", tbl_insert), ("remove", tbl_remove), ("concat", tbl_concat)]:
            table_lib.rawset(name, self._wrap_builtin("table."+name, fn))

        g.update({
            "print":        self._wrap_builtin("print", lua_print),
            "tostring":     self._wrap_builtin("tostring", lua_tostring),
            "tonumber":     self._wrap_builtin("tonumber", lua_tonumber),
            "type":         self._wrap_builtin("type", lua_type),
            "error":        self._wrap_builtin("error", lua_error),
            "assert":       self._wrap_builtin("assert", lua_assert),
            "pcall":        self._wrap_builtin("pcall", lua_pcall),
            "unpack":       self._wrap_builtin("unpack", lua_unpack),
            "select":       self._wrap_builtin("select", lua_select),
            "rawget":       self._wrap_builtin("rawget", lua_rawget),
            "rawset":       self._wrap_builtin("rawset", lua_rawset),
            "setmetatable": self._wrap_builtin("setmetatable", lua_setmetatable),
            "getmetatable": self._wrap_builtin("getmetatable", lua_getmetatable),
            "string":       string_lib,
            "math":         math_lib,
            "os":           os_lib,
            "table":        table_lib,
            "ipairs":       self._wrap_builtin("ipairs", lua_ipairs),
            "pairs":        self._wrap_builtin("pairs", lua_pairs),
            "_VERSION":     "LuaR 1.0",
        })
        return g

    def _wrap_builtin(self, name, fn):
        class Builtin:
            def __init__(self, n, f):
                self.name = n
                self.fn = f
            def __call__(self, *args):
                return self.fn(*args)
            def __repr__(self):
                return f"<builtin {self.name}>"
        return Builtin(name, fn)

    def call(self, fn, args):
        if callable(fn):
            result = fn(*args)
            # some builtins return tuples
            if isinstance(result, tuple):
                return result[0] if result else None
            return result

        if isinstance(fn, LuaClosure):
            locals_ = list(fn.upvalues.values()) if fn.upvalues else []
            # Extend locals to cover param slots
            n_params = len(fn.params)
            # Pre-size locals list
            frame_locals = [None] * max(n_params, 64)
            for i, p in enumerate(fn.params):
                frame_locals[i] = args[i] if i < len(args) else None
            return self._exec(fn.instructions, fn.constants, frame_locals)

        raise LuaRuntimeError(f"Attempt to call a {type(fn).__name__} value")

    def _exec(self, instructions, constants, locals_=None):
        stack = []
        pc = 0
        locals_ = locals_ or [None] * 64

        def ensure_locals(slot):
            nonlocal locals_
            while len(locals_) <= slot:
                locals_.extend([None] * 32)

        while pc < len(instructions):
            op, operand = instructions[pc]
            pc += 1

            if op == Op.LOAD_CONST:
                stack.append(constants[operand])

            elif op == Op.LOAD_NIL:
                stack.append(None)

            elif op == Op.LOAD_TRUE:
                stack.append(True)

            elif op == Op.LOAD_FALSE:
                stack.append(False)

            elif op == Op.LOAD_LOCAL:
                ensure_locals(operand)
                stack.append(locals_[operand])

            elif op == Op.STORE_LOCAL:
                ensure_locals(operand)
                locals_[operand] = stack.pop()

            elif op == Op.LOAD_GLOBAL:
                name = constants[operand]
                # support dotted names like "math.floor"
                if "." in str(name):
                    parts = str(name).split(".")
                    obj = self.globals.get(parts[0])
                    for part in parts[1:]:
                        if isinstance(obj, LuaTable):
                            obj = obj.rawget(part)
                        else:
                            obj = None
                    stack.append(obj)
                else:
                    stack.append(self.globals.get(name))

            elif op == Op.STORE_GLOBAL:
                name = constants[operand]
                self.globals[name] = stack.pop()

            elif op == Op.CALL:
                n_args = operand
                args = stack[-n_args:] if n_args else []
                fn = stack[-(n_args + 1)]
                stack = stack[:-(n_args + 1)]
                result = self.call(fn, args)
                stack.append(result)

            elif op == Op.RETURN:
                return stack.pop() if stack else None

            elif op == Op.JUMP:
                pc = operand

            elif op == Op.JUMP_IF_FALSE:
                v = stack.pop()
                if not v and v is not True:
                    pc = operand

            elif op == Op.JUMP_IF_TRUE:
                v = stack.pop()
                if v and v is not False and v is not None:
                    pc = operand

            elif op == Op.POP:
                if stack:
                    stack.pop()

            elif op == Op.DUP:
                if stack:
                    stack.append(stack[-1])

            elif op == Op.ADD:
                b, a = stack.pop(), stack.pop()
                stack.append(_arith(a, b, "+"))

            elif op == Op.SUB:
                b, a = stack.pop(), stack.pop()
                stack.append(_arith(a, b, "-"))

            elif op == Op.MUL:
                b, a = stack.pop(), stack.pop()
                stack.append(_arith(a, b, "*"))

            elif op == Op.DIV:
                b, a = stack.pop(), stack.pop()
                stack.append(_arith(a, b, "/"))

            elif op == 0x16:  # POW
                b, a = stack.pop(), stack.pop()
                stack.append(float(a) ** float(b))

            elif op == Op.MOD:
                b, a = stack.pop(), stack.pop()
                stack.append(_arith(a, b, "%"))

            elif op == Op.CONCAT:
                b, a = stack.pop(), stack.pop()
                stack.append(_tostring(a) + _tostring(b))

            elif op == Op.EQ:
                b, a = stack.pop(), stack.pop()
                stack.append(_lua_equal(a, b))

            elif op == Op.NEQ:
                b, a = stack.pop(), stack.pop()
                stack.append(not _lua_equal(a, b))

            elif op == Op.LT:
                b, a = stack.pop(), stack.pop()
                stack.append(a < b)

            elif op == Op.LE:
                b, a = stack.pop(), stack.pop()
                stack.append(a <= b)

            elif op == Op.GT:
                b, a = stack.pop(), stack.pop()
                stack.append(a > b)

            elif op == Op.GE:
                b, a = stack.pop(), stack.pop()
                stack.append(a >= b)

            elif op == Op.AND:
                b, a = stack.pop(), stack.pop()
                stack.append(b if a else a)

            elif op == Op.OR:
                b, a = stack.pop(), stack.pop()
                stack.append(a if a else b)

            elif op == Op.NOT:
                a = stack.pop()
                stack.append(not a if a is not None else True)

            elif op == Op.NEG:
                a = stack.pop()
                stack.append(-a)

            elif op == 0x34:  # LEN
                a = stack.pop()
                if isinstance(a, str):
                    stack.append(len(a))
                elif isinstance(a, LuaTable):
                    stack.append(len(a))
                else:
                    stack.append(0)

            elif op == Op.NEW_TABLE:
                stack.append(LuaTable())

            elif op == Op.SET_FIELD:
                # stack: ... [table, key, value]  (value on top)
                value = stack.pop()
                key   = stack.pop()
                table = stack.pop()
                if isinstance(table, LuaTable):
                    table.rawset(key, value)

            elif op == Op.GET_FIELD:
                key   = stack.pop()
                table = stack.pop()
                if isinstance(table, LuaTable):
                    stack.append(table.rawget(key))
                elif isinstance(table, str):
                    # string methods
                    lib = self.globals.get("string")
                    if isinstance(lib, LuaTable):
                        stack.append(lib.rawget(key))
                    else:
                        stack.append(None)
                else:
                    stack.append(None)

            elif op == Op.MAKE_CLOSURE:
                fn_json = constants[operand]
                fn_obj = json.loads(fn_json)
                instructions_raw = [(i[0], i[1]) for i in fn_obj["instructions"]]
                closure = LuaClosure(
                    fn_obj["params"],
                    instructions_raw,
                    fn_obj["constants"],
                )
                stack.append(closure)

            elif op == 0x61:  # SWAP
                if len(stack) >= 2:
                    stack[-1], stack[-2] = stack[-2], stack[-1]

            else:
                pass  # unknown opcode — skip

        return None


def _arith(a, b, op):
    try:
        a = float(a) if isinstance(a, str) else a
        b = float(b) if isinstance(b, str) else b
        if op == "+": result = a + b
        elif op == "-": result = a - b
        elif op == "*": result = a * b
        elif op == "/": result = a / b
        elif op == "%": result = a % b
        else: result = 0
        # Return int if both operands were int-like and result is whole
        if isinstance(result, float) and result == int(result):
            return int(result)
        return result
    except (TypeError, ZeroDivisionError) as e:
        raise LuaRuntimeError(f"Arithmetic error: {e}")


# ─────────────────────────── Public API ─────────────────────────────────────

def execute_instructions(payload: bytes) -> None:
    """Decompile and execute a decrypted payload."""
    instructions, constants = decompile_payload(payload)
    vm = VM()
    vm._exec(instructions, constants)
