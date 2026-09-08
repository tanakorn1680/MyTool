"""
LuaR Compiler: Lua source → Internal Instruction Representation

Supports a practical subset of Lua:
  - local variable declarations
  - assignment (global and local)
  - arithmetic, comparison, logical expressions
  - if/elseif/else/end
  - while/do/end
  - for numeric (for i=start,stop[,step] do ... end)
  - function calls (including nested, chained)
  - print, tostring, tonumber, type builtins
  - string/number/boolean/nil literals
  - return statement
  - not, unary minus
  - string concatenation (..)
  - table constructors {} and field access t.k / t[k]
  - function definitions (local function f(...) ... end)
"""

import re
import struct
import json
from enum import IntEnum


# ─────────────────────────── Opcodes ────────────────────────────────────────

class Op(IntEnum):
    LOAD_CONST    = 0x01
    LOAD_NIL      = 0x02
    LOAD_TRUE     = 0x03
    LOAD_FALSE    = 0x04
    LOAD_LOCAL    = 0x05
    STORE_LOCAL   = 0x06
    LOAD_GLOBAL   = 0x07
    STORE_GLOBAL  = 0x08
    CALL          = 0x09   # operand = arg count
    RETURN        = 0x0A
    JUMP          = 0x0B   # operand = absolute instruction index
    JUMP_IF_FALSE = 0x0C
    JUMP_IF_TRUE  = 0x0D
    POP           = 0x0E
    ADD           = 0x10
    SUB           = 0x11
    MUL           = 0x12
    DIV           = 0x13
    MOD           = 0x14
    CONCAT        = 0x15
    EQ            = 0x20
    NEQ           = 0x21
    LT            = 0x22
    LE            = 0x23
    GT            = 0x24
    GE            = 0x25
    AND           = 0x30
    OR            = 0x31
    NOT           = 0x32
    NEG           = 0x33
    NEW_TABLE     = 0x40
    SET_FIELD     = 0x41   # pops key, value, table; pushes nothing
    GET_FIELD     = 0x42   # pops key, table; pushes value
    MAKE_CLOSURE  = 0x50   # operand = function index in constants
    DUP           = 0x60


# ─────────────────────────── Tokeniser ──────────────────────────────────────

TK_NUM    = "NUM"
TK_STR    = "STR"
TK_NAME   = "NAME"
TK_EOF    = "EOF"

KEYWORDS = {
    "and","break","do","else","elseif","end","false","for",
    "function","if","in","local","nil","not","or","repeat",
    "return","then","true","until","while",
}

TOKEN_RE = re.compile(
    r'--\[\[.*?\]\]|--[^\n]*'          # comments
    r'|"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\''  # strings
    r'|\[\[.*?\]\]'                     # long strings
    r'|0x[0-9a-fA-F]+'                 # hex numbers
    r'|\d+\.?\d*(?:[eE][+-]?\d+)?'     # numbers
    r'|[a-zA-Z_]\w*'                   # identifiers/keywords
    r'|\.\.'                            # concat
    r'|\.\.\.'                          # vararg (ignored)
    r'|[=<>~]=|[+\-*/%^#<>=(){}[\],;:.&|]',  # operators & punct
    re.DOTALL
)


def tokenise(src):
    tokens = []
    for m in TOKEN_RE.finditer(src):
        t = m.group()
        if t.startswith("--") or t.startswith("--[["):
            continue
        if t[0] in ('"', "'") or t.startswith("[["):
            tokens.append((TK_STR, _unescape(t)))
        elif re.match(r'^0x|^\d', t):
            tokens.append((TK_NUM, float(t) if '.' in t or 'e' in t.lower() else int(t, 0)))
        elif t in KEYWORDS:
            tokens.append((t, t))
        elif re.match(r'^[a-zA-Z_]', t):
            tokens.append((TK_NAME, t))
        else:
            tokens.append((t, t))
    tokens.append((TK_EOF, None))
    return tokens


def _unescape(s):
    if s.startswith("[["):
        return s[2:-2]
    inner = s[1:-1]
    return inner.encode("raw_unicode_escape").decode("unicode_escape")


# ─────────────────────────── Parser ─────────────────────────────────────────

class ParseError(Exception):
    pass


class Parser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.pos = 0

    def peek(self):
        return self.tokens[self.pos]

    def peek_type(self):
        return self.tokens[self.pos][0]

    def advance(self):
        t = self.tokens[self.pos]
        self.pos += 1
        return t

    def expect(self, kind):
        t = self.advance()
        if t[0] != kind:
            raise ParseError(f"Expected {kind!r}, got {t[0]!r} ({t[1]!r})")
        return t

    def match(self, *kinds):
        if self.peek_type() in kinds:
            return self.advance()
        return None

    # ── Block ──

    def parse_block(self, stop=("end", "else", "elseif", "until", TK_EOF)):
        stmts = []
        while self.peek_type() not in stop:
            s = self.parse_stmt()
            if s:
                stmts.append(s)
            if s and s[0] == "return":
                break
        return ("block", stmts)

    # ── Statement ──

    def parse_stmt(self):
        self.match(";")
        t = self.peek_type()

        if t == "local":
            return self.parse_local()
        elif t == "if":
            return self.parse_if()
        elif t == "while":
            return self.parse_while()
        elif t == "for":
            return self.parse_for()
        elif t == "return":
            return self.parse_return()
        elif t == "function":
            return self.parse_function_stmt()
        elif t == "do":
            self.advance()
            b = self.parse_block()
            self.expect("end")
            return b
        elif t == "break":
            self.advance()
            return ("break",)
        elif t in (TK_NAME, "("):
            return self.parse_expr_stmt()
        elif t == TK_EOF:
            return None
        else:
            # skip unknown token
            self.advance()
            return None

    def parse_local(self):
        self.expect("local")
        if self.peek_type() == "function":
            self.advance()
            name = self.expect(TK_NAME)[1]
            fn = self.parse_funcbody()
            return ("local_func", name, fn)
        names = [self.expect(TK_NAME)[1]]
        while self.match(","):
            names.append(self.expect(TK_NAME)[1])
        exprs = []
        if self.match("="):
            exprs.append(self.parse_expr())
            while self.match(","):
                exprs.append(self.parse_expr())
        return ("local", names, exprs)

    def parse_if(self):
        self.expect("if")
        cond = self.parse_expr()
        self.expect("then")
        body = self.parse_block(stop=("end","else","elseif",TK_EOF))
        elseifs = []
        else_body = None
        while self.peek_type() == "elseif":
            self.advance()
            ec = self.parse_expr()
            self.expect("then")
            eb = self.parse_block(stop=("end","else","elseif",TK_EOF))
            elseifs.append((ec, eb))
        if self.match("else"):
            else_body = self.parse_block(stop=("end",TK_EOF))
        self.expect("end")
        return ("if", cond, body, elseifs, else_body)

    def parse_while(self):
        self.expect("while")
        cond = self.parse_expr()
        self.expect("do")
        body = self.parse_block()
        self.expect("end")
        return ("while", cond, body)

    def parse_for(self):
        self.expect("for")
        var = self.expect(TK_NAME)[1]
        self.expect("=")
        start = self.parse_expr()
        self.expect(",")
        stop = self.parse_expr()
        step = None
        if self.match(","):
            step = self.parse_expr()
        self.expect("do")
        body = self.parse_block()
        self.expect("end")
        return ("for_num", var, start, stop, step, body)

    def parse_return(self):
        self.expect("return")
        exprs = []
        if self.peek_type() not in ("end","else","elseif","until",TK_EOF,";"):
            exprs.append(self.parse_expr())
            while self.match(","):
                exprs.append(self.parse_expr())
        self.match(";")
        return ("return", exprs)

    def parse_function_stmt(self):
        self.expect("function")
        name = self.expect(TK_NAME)[1]
        # handle dotted names as global string key
        while self.match("."):
            field = self.expect(TK_NAME)[1]
            name = name + "." + field
        fn = self.parse_funcbody()
        return ("assign", ("name", name), fn)

    def parse_funcbody(self):
        self.expect("(")
        params = []
        if self.peek_type() != ")":
            params.append(self.expect(TK_NAME)[1])
            while self.match(","):
                if self.peek_type() == "...":
                    self.advance(); break
                params.append(self.expect(TK_NAME)[1])
        self.expect(")")
        body = self.parse_block()
        self.expect("end")
        return ("function", params, body)

    def parse_expr_stmt(self):
        expr = self.parse_suffixed_expr()
        if self.peek_type() == "=":
            self.advance()
            value = self.parse_expr()
            return ("assign", expr, value)
        if self.match(","):
            # multiple assign: a, b = x, y
            targets = [expr]
            targets.append(self.parse_suffixed_expr())
            while self.match(","):
                targets.append(self.parse_suffixed_expr())
            self.expect("=")
            values = [self.parse_expr()]
            while self.match(","):
                values.append(self.parse_expr())
            return ("multi_assign", targets, values)
        # standalone call
        return ("call_stmt", expr)

    # ── Expressions ──

    def parse_expr(self):
        return self.parse_or()

    def parse_or(self):
        left = self.parse_and()
        while self.peek_type() == "or":
            self.advance()
            right = self.parse_and()
            left = ("binop", "or", left, right)
        return left

    def parse_and(self):
        left = self.parse_comparison()
        while self.peek_type() == "and":
            self.advance()
            right = self.parse_comparison()
            left = ("binop", "and", left, right)
        return left

    def parse_comparison(self):
        left = self.parse_concat()
        while self.peek_type() in ("<","<=",">",">=","==","~="):
            op = self.advance()[0]
            right = self.parse_concat()
            left = ("binop", op, left, right)
        return left

    def parse_concat(self):
        left = self.parse_additive()
        if self.peek_type() == "..":
            self.advance()
            right = self.parse_concat()  # right-associative
            return ("binop", "..", left, right)
        return left

    def parse_additive(self):
        left = self.parse_multiplicative()
        while self.peek_type() in ("+", "-"):
            op = self.advance()[0]
            right = self.parse_multiplicative()
            left = ("binop", op, left, right)
        return left

    def parse_multiplicative(self):
        left = self.parse_unary()
        while self.peek_type() in ("*", "/", "%"):
            op = self.advance()[0]
            right = self.parse_unary()
            left = ("binop", op, left, right)
        return left

    def parse_unary(self):
        if self.peek_type() == "not":
            self.advance()
            return ("unop", "not", self.parse_unary())
        if self.peek_type() == "-":
            self.advance()
            return ("unop", "-", self.parse_unary())
        if self.peek_type() == "#":
            self.advance()
            return ("unop", "#", self.parse_unary())
        return self.parse_power()

    def parse_power(self):
        base = self.parse_suffixed_expr()
        if self.peek_type() == "^":
            self.advance()
            exp = self.parse_unary()
            return ("binop", "^", base, exp)
        return base

    def parse_suffixed_expr(self):
        base = self.parse_primary()
        while True:
            if self.peek_type() == ".":
                self.advance()
                key = self.expect(TK_NAME)[1]
                base = ("index", base, ("const", key))
            elif self.peek_type() == "[":
                self.advance()
                key = self.parse_expr()
                self.expect("]")
                base = ("index", base, key)
            elif self.peek_type() == "(":
                args = self.parse_args()
                base = ("call", base, args)
            elif self.peek_type() == ":":
                self.advance()
                method = self.expect(TK_NAME)[1]
                args = self.parse_args()
                base = ("method_call", base, method, args)
            elif self.peek_type() == TK_STR:
                # f "string" shorthand
                s = self.advance()[1]
                base = ("call", base, [("const", s)])
            elif self.peek_type() == "{":
                tbl = self.parse_table()
                base = ("call", base, [tbl])
            else:
                break
        return base

    def parse_primary(self):
        t = self.peek_type()
        if t == TK_NUM:
            v = self.advance()[1]
            return ("const", v)
        if t == TK_STR:
            v = self.advance()[1]
            return ("const", v)
        if t == "true":
            self.advance()
            return ("const", True)
        if t == "false":
            self.advance()
            return ("const", False)
        if t == "nil":
            self.advance()
            return ("const", None)
        if t == "...":
            self.advance()
            return ("vararg",)
        if t == TK_NAME:
            name = self.advance()[1]
            return ("name", name)
        if t == "(":
            self.advance()
            e = self.parse_expr()
            self.expect(")")
            return e
        if t == "{":
            return self.parse_table()
        if t == "function":
            self.advance()
            return self.parse_funcbody()
        raise ParseError(f"Unexpected token {t!r} at pos {self.pos}")

    def parse_args(self):
        self.expect("(")
        args = []
        if self.peek_type() != ")":
            args.append(self.parse_expr())
            while self.match(","):
                args.append(self.parse_expr())
        self.expect(")")
        return args

    def parse_table(self):
        self.expect("{")
        fields = []
        while self.peek_type() != "}":
            if self.peek_type() == "[":
                self.advance()
                key = self.parse_expr()
                self.expect("]")
                self.expect("=")
                val = self.parse_expr()
                fields.append(("kv", key, val))
            elif self.peek_type() == TK_NAME and self.tokens[self.pos+1][0] == "=":
                key = self.advance()[1]
                self.advance()  # =
                val = self.parse_expr()
                fields.append(("kv", ("const", key), val))
            else:
                val = self.parse_expr()
                fields.append(("arr", val))
            self.match(",")
            self.match(";")
        self.expect("}")
        return ("table", fields)


def parse_lua(source):
    tokens = tokenise(source)
    p = Parser(tokens)
    return p.parse_block(stop=(TK_EOF,))


# ─────────────────────────── Code Generator ─────────────────────────────────

class CodeGen:
    def __init__(self):
        self.instructions = []   # list of (opcode, operand)
        self.constants = []      # pooled constants
        self.const_map = {}
        self.locals_stack = [{}] # stack of scope dicts {name: slot}
        self.local_count = [0]   # per-scope slot counter
        self.break_patches = []  # list of lists for break jumps

    # ── Constant pool ──

    def const_idx(self, val):
        key = (type(val).__name__, val)
        if key not in self.const_map:
            self.const_map[key] = len(self.constants)
            self.constants.append(val)
        return self.const_map[key]

    # ── Emit ──

    def emit(self, op, operand=0):
        self.instructions.append((int(op), operand))
        return len(self.instructions) - 1

    def patch(self, idx, target):
        op, _ = self.instructions[idx]
        self.instructions[idx] = (op, target)

    def here(self):
        return len(self.instructions)

    # ── Scope ──

    def push_scope(self):
        self.locals_stack.append({})
        self.local_count.append(self._total_locals())

    def pop_scope(self):
        self.locals_stack.pop()
        self.local_count.pop()

    def _total_locals(self):
        return sum(len(s) for s in self.locals_stack)

    def define_local(self, name):
        slot = self._total_locals()
        self.locals_stack[-1][name] = slot
        return slot

    def resolve_local(self, name):
        for scope in reversed(self.locals_stack):
            if name in scope:
                return scope[name]
        return None

    # ── Expression compilation ──

    def compile_expr(self, node):
        kind = node[0]

        if kind == "const":
            v = node[1]
            if v is None:
                self.emit(Op.LOAD_NIL)
            elif v is True:
                self.emit(Op.LOAD_TRUE)
            elif v is False:
                self.emit(Op.LOAD_FALSE)
            else:
                self.emit(Op.LOAD_CONST, self.const_idx(v))

        elif kind == "name":
            name = node[1]
            slot = self.resolve_local(name)
            if slot is not None:
                self.emit(Op.LOAD_LOCAL, slot)
            else:
                self.emit(Op.LOAD_GLOBAL, self.const_idx(name))

        elif kind == "binop":
            op = node[1]
            if op == "and":
                self.compile_expr(node[2])
                self.emit(Op.DUP)
                j = self.emit(Op.JUMP_IF_FALSE, 0)
                self.emit(Op.POP)
                self.compile_expr(node[3])
                self.patch(j, self.here())
            elif op == "or":
                self.compile_expr(node[2])
                self.emit(Op.DUP)
                j = self.emit(Op.JUMP_IF_TRUE, 0)
                self.emit(Op.POP)
                self.compile_expr(node[3])
                self.patch(j, self.here())
            else:
                self.compile_expr(node[2])
                self.compile_expr(node[3])
                opmap = {
                    "+": Op.ADD, "-": Op.SUB, "*": Op.MUL,
                    "/": Op.DIV, "%": Op.MOD,
                    "..": Op.CONCAT,
                    "==": Op.EQ, "~=": Op.NEQ,
                    "<": Op.LT, "<=": Op.LE,
                    ">": Op.GT, ">=": Op.GE,
                    "^": Op.MUL,  # placeholder, runtime handles
                }
                self.emit(opmap.get(op, Op.ADD))
                if op == "^":
                    # patch: we want POW — reuse DIV slot and handle in runtime
                    idx = len(self.instructions) - 1
                    self.instructions[idx] = (0x13, 0)  # DIV
                    # Actually emit a special opcode via const call
                    # Simplify: emit as a math.pow call pattern
                    # Revert: encode ^ as special DIV opcode 0x16
                    self.instructions[idx] = (0x16, 0)

        elif kind == "unop":
            op = node[1]
            self.compile_expr(node[2])
            if op == "not":
                self.emit(Op.NOT)
            elif op == "-":
                self.emit(Op.NEG)
            elif op == "#":
                self.emit(Op.LOAD_GLOBAL, self.const_idx("__len__"))
                # push the operand below the function and call
                # actually: emit LEN opcode 0x34
                # pop the __len__ load, use dedicated opcode
                self.instructions.pop()
                self.emit(0x34)

        elif kind == "call":
            self.compile_expr(node[1])
            for a in node[2]:
                self.compile_expr(a)
            self.emit(Op.CALL, len(node[2]))

        elif kind == "method_call":
            # push obj, then call obj:method(args)
            self.compile_expr(node[1])
            self.emit(Op.DUP)
            self.emit(Op.LOAD_CONST, self.const_idx(node[2]))
            self.emit(Op.GET_FIELD)
            # swap: stack is [obj, method] but we need [method, obj, args]
            # emit a SWAP opcode 0x61
            self.emit(0x61)
            for a in node[3]:
                self.compile_expr(a)
            self.emit(Op.CALL, len(node[3]) + 1)

        elif kind == "index":
            self.compile_expr(node[1])
            self.compile_expr(node[2])
            self.emit(Op.GET_FIELD)

        elif kind == "table":
            self.emit(Op.NEW_TABLE)
            arr_idx = [0]
            for f in node[1]:
                if f[0] == "arr":
                    self.emit(Op.DUP)
                    self.emit(Op.LOAD_CONST, self.const_idx(arr_idx[0] + 1))
                    self.compile_expr(f[1])
                    self.emit(Op.SET_FIELD)
                    arr_idx[0] += 1
                elif f[0] == "kv":
                    self.emit(Op.DUP)
                    self.compile_expr(f[1])
                    self.compile_expr(f[2])
                    self.emit(Op.SET_FIELD)

        elif kind == "function":
            params, body = node[1], node[2]
            sub = CodeGen()
            # bind params as locals in sub-codegen
            for p in params:
                sub.define_local(p)
            sub.compile_block(body)
            sub.emit(Op.LOAD_NIL)
            sub.emit(Op.RETURN)
            fn_obj = {
                "params": params,
                "instructions": sub.instructions,
                "constants": sub.constants,
            }
            self.emit(Op.MAKE_CLOSURE, self.const_idx(json.dumps(fn_obj, default=str)))

        elif kind == "vararg":
            self.emit(Op.LOAD_NIL)  # placeholder

        else:
            self.emit(Op.LOAD_NIL)

    # ── Statement compilation ──

    def compile_block(self, node):
        for stmt in node[1]:
            if stmt:
                self.compile_stmt(stmt)

    def compile_stmt(self, node):
        kind = node[0]

        if kind == "block":
            self.push_scope()
            for s in node[1]:
                if s:
                    self.compile_stmt(s)
            self.pop_scope()

        elif kind == "local":
            names, exprs = node[1], node[2]
            for i, name in enumerate(names):
                if i < len(exprs):
                    self.compile_expr(exprs[i])
                else:
                    self.emit(Op.LOAD_NIL)
                slot = self.define_local(name)
                self.emit(Op.STORE_LOCAL, slot)

        elif kind == "local_func":
            name, fn = node[1], node[2]
            slot = self.define_local(name)
            self.compile_expr(fn)
            self.emit(Op.DUP)           # keep copy on stack
            self.emit(Op.STORE_LOCAL, slot)
            # Also store in globals so recursive calls via LOAD_GLOBAL find it
            self.emit(Op.STORE_GLOBAL, self.const_idx(name))

        elif kind == "assign":
            target, value = node[1], node[2]
            self.compile_expr(value)
            self._store_target(target)

        elif kind == "multi_assign":
            targets, values = node[1], node[2]
            for i, t in enumerate(targets):
                if i < len(values):
                    self.compile_expr(values[i])
                else:
                    self.emit(Op.LOAD_NIL)
            for t in reversed(targets):
                self._store_target(t)

        elif kind == "call_stmt":
            self.compile_expr(node[1])
            self.emit(Op.POP)

        elif kind == "if":
            _, cond, body, elseifs, else_body = node
            end_jumps = []

            self.compile_expr(cond)
            j_false = self.emit(Op.JUMP_IF_FALSE, 0)
            self.compile_block(body)
            end_jumps.append(self.emit(Op.JUMP, 0))
            self.patch(j_false, self.here())

            for ec, eb in elseifs:
                self.compile_expr(ec)
                jf = self.emit(Op.JUMP_IF_FALSE, 0)
                self.compile_block(eb)
                end_jumps.append(self.emit(Op.JUMP, 0))
                self.patch(jf, self.here())

            if else_body:
                self.compile_block(else_body)

            for j in end_jumps:
                self.patch(j, self.here())

        elif kind == "while":
            _, cond, body = node
            loop_start = self.here()
            self.break_patches.append([])
            self.compile_expr(cond)
            j_exit = self.emit(Op.JUMP_IF_FALSE, 0)
            self.compile_block(body)
            self.emit(Op.JUMP, loop_start)
            exit_addr = self.here()
            self.patch(j_exit, exit_addr)
            for bp in self.break_patches.pop():
                self.patch(bp, exit_addr)

        elif kind == "for_num":
            _, var, start, stop_expr, step_expr, body = node
            self.push_scope()
            # allocate hidden slots for limit and step
            self.compile_expr(start)
            idx_slot = self.define_local(var)
            self.emit(Op.STORE_LOCAL, idx_slot)

            self.compile_expr(stop_expr)
            lim_slot = self.define_local("__lim__")
            self.emit(Op.STORE_LOCAL, lim_slot)

            if step_expr:
                self.compile_expr(step_expr)
            else:
                self.emit(Op.LOAD_CONST, self.const_idx(1))
            step_slot = self.define_local("__step__")
            self.emit(Op.STORE_LOCAL, step_slot)

            loop_start = self.here()
            self.break_patches.append([])

            # condition: idx <= lim (for positive step)
            self.emit(Op.LOAD_LOCAL, idx_slot)
            self.emit(Op.LOAD_LOCAL, lim_slot)
            self.emit(Op.LE)
            j_exit = self.emit(Op.JUMP_IF_FALSE, 0)

            self.compile_block(body)

            # increment
            self.emit(Op.LOAD_LOCAL, idx_slot)
            self.emit(Op.LOAD_LOCAL, step_slot)
            self.emit(Op.ADD)
            self.emit(Op.STORE_LOCAL, idx_slot)

            self.emit(Op.JUMP, loop_start)
            exit_addr = self.here()
            self.patch(j_exit, exit_addr)
            for bp in self.break_patches.pop():
                self.patch(bp, exit_addr)
            self.pop_scope()

        elif kind == "return":
            exprs = node[1]
            if exprs:
                self.compile_expr(exprs[0])
            else:
                self.emit(Op.LOAD_NIL)
            self.emit(Op.RETURN)

        elif kind == "break":
            j = self.emit(Op.JUMP, 0)
            if self.break_patches:
                self.break_patches[-1].append(j)

    def _store_target(self, target):
        kind = target[0]
        if kind == "name":
            name = target[1]
            slot = self.resolve_local(name)
            if slot is not None:
                self.emit(Op.STORE_LOCAL, slot)
            else:
                self.emit(Op.STORE_GLOBAL, self.const_idx(name))
        elif kind == "index":
            # value is already on stack; compile table and key
            obj, key = target[1], target[2]
            self.compile_expr(obj)
            self.compile_expr(key)
            self.emit(Op.SET_FIELD)
        else:
            self.emit(Op.POP)


# ─────────────────────────── Serialization ──────────────────────────────────

def _serialize_instructions(instructions):
    """Pack instructions as bytes: 1 byte opcode + 4 bytes operand (little-endian)"""
    out = bytearray()
    for op, operand in instructions:
        out += bytes([op & 0xFF])
        out += struct.pack("<i", operand)
    return bytes(out)


def _serialize_constants(constants):
    """Pack constant pool as JSON bytes"""
    return json.dumps(constants, default=str).encode("utf-8")


def serialize_program(instructions, constants):
    instr_bytes = _serialize_instructions(instructions)
    const_bytes = _serialize_constants(constants)
    # Format: [4 instr_len][instr_bytes][4 const_len][const_bytes]
    data = struct.pack("<I", len(instr_bytes)) + instr_bytes
    data += struct.pack("<I", len(const_bytes)) + const_bytes
    return data


def deserialize_program(data):
    offset = 0
    instr_len = struct.unpack_from("<I", data, offset)[0]
    offset += 4
    instr_bytes = data[offset:offset+instr_len]
    offset += instr_len

    const_len = struct.unpack_from("<I", data, offset)[0]
    offset += 4
    const_bytes = data[offset:offset+const_len]

    instructions = []
    for i in range(0, len(instr_bytes), 5):
        op = instr_bytes[i]
        operand = struct.unpack_from("<i", instr_bytes, i+1)[0]
        instructions.append((op, operand))

    constants = json.loads(const_bytes.decode("utf-8"))
    return instructions, constants


# ─────────────────────────── Obfuscator ─────────────────────────────────────

def obfuscate(instructions, constants):
    """
    Simple instruction remapping: shuffle opcode values via a fixed permutation
    so static analysis of the binary cannot directly match standard opcodes.
    The runtime applies the inverse map before executing.
    """
    import random
    rng = random.Random(0x4C756152)  # deterministic seed "LuaR"

    # Build a remapping table for the 256 possible byte values
    perm = list(range(256))
    rng.shuffle(perm)
    inv_perm = [0] * 256
    for i, v in enumerate(perm):
        inv_perm[v] = i

    remapped = [(perm[op], operand) for op, operand in instructions]
    return remapped, constants, perm


# ─────────────────────────── Public API ─────────────────────────────────────

def compile_lua(source: str) -> bytes:
    """
    Parse Lua source → compile to internal IR → obfuscate → serialize.
    Returns raw bytes suitable for encryption.
    """
    ast = parse_lua(source)
    gen = CodeGen()
    gen.compile_block(ast)
    gen.emit(Op.LOAD_NIL)
    gen.emit(Op.RETURN)

    remapped_instr, constants, perm = obfuscate(gen.instructions, gen.constants)

    # Pack obfuscation permutation + program
    perm_bytes = bytes(perm)  # 256 bytes
    prog_bytes = serialize_program(remapped_instr, constants)
    return perm_bytes + prog_bytes


def decompile_payload(data: bytes):
    """
    Inverse of compile_lua: extract obfuscation table and program.
    Returns (instructions, constants) ready for execution.
    """
    perm = list(data[:256])
    inv_perm = [0] * 256
    for i, v in enumerate(perm):
        inv_perm[v] = i

    prog_bytes = data[256:]
    instructions, constants = deserialize_program(prog_bytes)

    # De-remap opcodes
    original = [(inv_perm[op], operand) for op, operand in instructions]
    return original, constants
