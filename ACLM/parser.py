"""ACLM parser — metal statement grammar."""

from __future__ import annotations
from typing import List, Optional, Any
from .lexer import Lexer, Tok, T
from . import ast_nodes as A


class Parser:
    def __init__(self, tokens: List[Tok], filename: str = "<src>"):
        self.tokens = tokens
        self.filename = filename
        self.i = 0

    def _t(self) -> Tok:
        return self.tokens[self.i] if self.i < len(self.tokens) else self.tokens[-1]

    def _adv(self) -> Tok:
        t = self._t()
        if t.kind != T.EOF:
            self.i += 1
        return t

    def _match(self, kind: T) -> bool:
        if self._t().kind == kind:
            self._adv()
            return True
        return False

    def _expect(self, kind: T, msg: str = "") -> Tok:
        t = self._t()
        if t.kind != kind:
            raise SyntaxError(
                f"{self.filename}:{t.line}:{t.col}: expected {kind.name}, got {t.kind.name}"
                + (f" ({msg})" if msg else "")
            )
        return self._adv()

    def _skip_nl(self):
        while self._match(T.NEWLINE):
            pass

    def parse(self) -> A.Program:
        stmts: List[A.Node] = []
        self._skip_nl()
        # optional @mode: metal / raw / low — accepted, ignored (ACLM is always metal)
        while self._t().kind != T.EOF:
            self._skip_nl()
            if self._t().kind == T.EOF:
                break
            if self._t().kind == T.IDENT and self._t().value.lower() in ("mode", "@mode"):
                # tolerate @mode: x lines if lexer split oddly — skip line
                while self._t().kind not in (T.NEWLINE, T.EOF):
                    self._adv()
                continue
            if self._t().kind == T.IDENT and self._t().value == "@mode":
                while self._t().kind not in (T.NEWLINE, T.EOF):
                    self._adv()
                continue
            stmts.append(self._statement())
            self._skip_nl()
        return A.Program(statements=stmts)

    def _statement(self) -> A.Node:
        t = self._t()
        if t.kind == T.LABEL:
            name = self._adv().value
            # bare label def if alone, or used later
            # label definition: ~name at start of stmt
            return A.Label(name=name, line=t.line, col=t.col)

        if t.kind != T.IDENT:
            raise SyntaxError(f"{self.filename}:{t.line}:{t.col}: expected statement")

        kw = t.value.lower()
        line, col = t.line, t.col

        # cpu:set style — IDENT may be "cpu" then COLON then IDENT
        if kw == "cpu":
            self._adv()
            self._expect(T.COLON)
            op = self._expect(T.IDENT).value.lower()
            return self._cpu(op, line, col)

        if kw == "data":
            self._adv()
            self._expect(T.COLON)
            what = self._expect(T.IDENT).value.lower()
            return self._data(what, line, col)

        if kw == "ram":
            self._adv()
            self._expect(T.COLON)
            what = self._expect(T.IDENT).value.lower()
            return self._ram(what, line, col)

        if kw == "sys":
            self._adv()
            self._expect(T.COLON)
            what = self._expect(T.IDENT).value.lower()
            if what != "call":
                raise SyntaxError(f"unknown sys:{what}")
            return self._syscall(line, col)

        if kw == "stack":
            self._adv()
            self._expect(T.COLON)
            what = self._expect(T.IDENT).value.lower()
            return self._stack(what, line, col)

        if kw == "cmp":
            self._adv()
            left = self._operand()
            self._expect(T.COMMA)
            right = self._operand()
            return A.Cmp(left=left, right=right, line=line, col=col)

        if kw == "jump_if":
            self._adv()
            cond = self._expect(T.IDENT).value.lower()
            lab = self._expect(T.LABEL).value
            return A.JumpIf(cond=cond, label=lab, line=line, col=col)

        if kw == "goto":
            self._adv()
            lab = self._expect(T.LABEL).value
            return A.Goto(label=lab, line=line, col=col)

        if kw == "call":
            self._adv()
            lab = self._expect(T.LABEL).value
            args = []
            while self._t().kind not in (T.NEWLINE, T.EOF):
                if self._match(T.COMMA):
                    continue
                args.append(self._operand())
            return A.Call(label=lab, args=args, line=line, col=col)

        if kw == "ret":
            self._adv()
            val = None
            if self._t().kind not in (T.NEWLINE, T.EOF):
                val = self._operand()
            if val is not None:
                return A.RetVal(value=val, line=line, col=col)
            return A.Ret(line=line, col=col)

        # Stage-2 unique full-control ops
        if kw == "blast":
            self._adv()
            self._expect(T.COLON)
            op = self._expect(T.IDENT).value.lower()
            return self._blast(op, line, col)

        if kw == "wire":
            self._adv()
            self._expect(T.COLON)
            op = self._expect(T.IDENT).value.lower()
            return self._wire(op, line, col)

        if kw == "trap":
            self._adv()
            self._expect(T.COLON)
            op = self._expect(T.IDENT).value.lower()
            if op != "neg":
                raise SyntaxError(f"unknown trap:{op}")
            lab = self._expect(T.LABEL).value
            return A.TrapNeg(label=lab, line=line, col=col)

        # Stage-3: cell / gate / pulse (mmap, atomics, time)
        if kw == "cell":
            self._adv()
            self._expect(T.COLON)
            op = self._expect(T.IDENT).value.lower()
            return self._cell(op, line, col)

        if kw == "gate":
            self._adv()
            self._expect(T.COLON)
            op = self._expect(T.IDENT).value.lower()
            return self._gate(op, line, col)

        if kw == "pulse":
            self._adv()
            self._expect(T.COLON)
            op = self._expect(T.IDENT).value.lower()
            return self._pulse(op, line, col)

        if kw == "target":
            self._adv()
            self._expect(T.COLON)
            op = self._expect(T.IDENT).value.lower()
            if op == "baremetal":
                return A.TargetBaremetal(line=line, col=col)
            raise SyntaxError(f"unknown target:{op}")

        if kw == "net":
            self._adv()
            self._expect(T.COLON)
            op = self._expect(T.IDENT).value.lower()
            return self._net(op, line, col)

        if kw == "sig":
            self._adv()
            self._expect(T.COLON)
            op = self._expect(T.IDENT).value.lower()
            if op == "action":
                signo = self._operand()
                if self._match(T.COMMA):
                    pass
                # handler: label or number
                if self._t().kind == T.LABEL:
                    h = self._adv().value
                    return A.SigAction(signo=signo, handler=h, line=line, col=col)
                hnum = self._operand()
                return A.SigAction(signo=signo, handler=str(getattr(hnum,'value', hnum)), line=line, col=col)
            if op == "return":
                return A.SigReturn(line=line, col=col)
            raise SyntaxError(f"unknown sig:{op}")
        if kw == "thread":
            self._adv()
            self._expect(T.COLON)
            op = self._expect(T.IDENT).value.lower()
            return self._thread(op, line, col)

        if kw == "section":
            self._adv()
            self._expect(T.COLON)
            name = self._expect(T.IDENT).value.lower()
            addr = 0
            if self._t().kind == T.IDENT and self._t().value.lower() == "at":
                self._adv()
                self._expect(T.COLON)
                addr = int(self._expect(T.NUMBER).value, 0)
            return A.SectionAt(name=name, addr=addr, line=line, col=col)

        if kw == "assert":
            self._adv()
            self._expect(T.COLON)
            what = self._expect(T.IDENT).value.lower()
            if what == "bytes":
                name = self._expect(T.IDENT).value
                # <= N or = N
                op = "le"
                if self._t().kind == T.IDENT and self._t().value in ("le", "eq", "lte"):
                    op = self._adv().value.lower()
                    if op == "lte":
                        op = "le"
                elif self._match(T.EQ):
                    op = "eq"
                else:
                    # accept literal <= as two tokens not available — use IDENT le or EQ
                    pass
                # optional symbol <= : if next is LT not in lexer, use NUMBER only after optional EQ
                if self._t().kind == T.EQ:
                    self._adv()
                    op = "eq"
                limit = int(self._expect(T.NUMBER).value, 0)
                return A.AssertBytes(name=name, limit=limit, op=op, line=line, col=col)
            if what == "size":
                which = self._expect(T.IDENT).value.lower()
                if self._t().kind == T.EQ:
                    self._adv()
                limit = int(self._expect(T.NUMBER).value, 0)
                return A.AssertSize(what=which, limit=limit, line=line, col=col)
            raise SyntaxError(f"unknown assert:{what}")

        if kw == "metal":
            self._adv()
            self._expect(T.COLON)
            op = self._expect(T.IDENT).value.lower()
            if op == "regs":
                return A.MetalRegs(line=line, col=col)
            if op == "deterministic":
                return A.MetalDeterministic(line=line, col=col)
            raise SyntaxError(f"unknown metal:{op}")

        if kw == "lock":
            self._adv()
            self._expect(T.COLON)
            return A.PrefixedOp(prefix="lock", line=line, col=col)
        if kw == "rep":
            self._adv()
            self._expect(T.COLON)
            return A.PrefixedOp(prefix="rep", line=line, col=col)

        if kw == "raw":
            self._adv()
            self._expect(T.COLON)
            # raw:begin ... raw:end  OR  raw: AA BB  OR  raw: "AA BB"
            parts = []
            if self._t().kind == T.IDENT and self._t().value.lower() == "begin":
                self._adv()
                self._skip_nl()
                while True:
                    if self._t().kind == T.EOF:
                        raise SyntaxError("unclosed raw:begin")
                    if self._t().kind == T.IDENT and self._t().value.lower() == "raw":
                        # peek raw:end
                        self._adv()
                        self._expect(T.COLON)
                        if self._expect(T.IDENT).value.lower() != "end":
                            raise SyntaxError("expected raw:end")
                        break
                    if self._t().kind == T.NEWLINE:
                        self._adv()
                        continue
                    if self._t().kind == T.STRING:
                        s = self._adv().value
                        for p in s.replace(",", " ").split():
                            parts.append(int(p, 16) & 0xFF)
                        continue
                    if self._match(T.COMMA):
                        continue
                    if self._t().kind == T.NUMBER:
                        v = self._adv().value
                        # raw bytes are hex-oriented: "31" means 0x31
                        if v.startswith(("0x","0X","0b","0B","0o","0O")):
                            parts.append(int(v, 0) & 0xFF)
                        else:
                            parts.append(int(v, 16) & 0xFF)
                        continue
                    if self._t().kind == T.IDENT:
                        parts.append(int(self._adv().value, 16) & 0xFF)
                        continue
                    raise SyntaxError(f"bad token in raw:begin: {self._t()}")
                return A.RawBytes(hex_parts=parts, line=line, col=col)
            if self._t().kind == T.STRING:
                s = self._adv().value
                for p in s.replace(",", " ").split():
                    parts.append(int(p, 16) & 0xFF)
            else:
                while self._t().kind not in (T.NEWLINE, T.EOF):
                    if self._match(T.COMMA):
                        continue
                    if self._t().kind == T.NUMBER:
                        v = self._adv().value
                        if v.startswith(("0x","0X","0b","0B","0o","0O")):
                            parts.append(int(v, 0) & 0xFF)
                        else:
                            parts.append(int(v, 16) & 0xFF)
                    elif self._t().kind == T.IDENT:
                        parts.append(int(self._adv().value, 16) & 0xFF)
                    else:
                        break
            return A.RawBytes(hex_parts=parts, line=line, col=col)

        if kw == "include":
            self._adv()
            self._expect(T.COLON)
            path = self._expect(T.STRING).value
            return A.Include(path=path, line=line, col=col)

        if kw == "flag" or kw == "flags":
            self._adv()
            self._expect(T.COLON)
            op = self._expect(T.IDENT).value.lower()
            if op == "setcc":
                dest = self._expect(T.IDENT).value
                self._expect(T.EQ)
                cond = self._expect(T.IDENT).value.lower()
                return A.FlagSetcc(dest=dest, cond=cond, line=line, col=col)
            if op == "clear":
                return A.FlagsClear(line=line, col=col)
            if op == "set":
                what = self._expect(T.IDENT).value.lower()
                if what != "df":
                    raise SyntaxError("flags:set only supports DF")
                return A.FlagsSetDF(line=line, col=col)
            raise SyntaxError(f"unknown flag:{op}")

        if kw == "chip":
            self._adv()
            self._expect(T.COLON)
            op = self._expect(T.IDENT).value.lower()
            return self._chip(op, line, col)

        if kw == "port":
            self._adv()
            self._expect(T.COLON)
            op = self._expect(T.IDENT).value.lower()
            return self._port(op, line, col)

        if kw == "vec":
            self._adv()
            self._expect(T.COLON)
            op = self._expect(T.IDENT).value.lower()
            return self._vec(op, line, col)

        # aliases for familiarity
        if kw == "mem":
            self._adv()
            self._expect(T.COLON)
            op = self._expect(T.IDENT).value.lower()
            if op == "set":
                return self._blast("fill", line, col)
            if op == "copy":
                return self._blast("copy", line, col)
            raise SyntaxError(f"unknown mem:{op}")

        if kw == "str":
            self._adv()
            self._expect(T.COLON)
            op = self._expect(T.IDENT).value.lower()
            return self._wire({"len": "len", "cmp": "cmp", "copy": "copy", "print": "emit", "emit": "emit"}[op] if op in ("len","cmp","copy","print","emit") else op, line, col)

        if kw == "err":
            self._adv()
            self._expect(T.COLON)
            op = self._expect(T.IDENT).value.lower()
            if op == "check":
                lab = self._expect(T.LABEL).value
                return A.TrapNeg(label=lab, line=line, col=col)
            if op == "status":
                dest = self._expect(T.IDENT).value
                return A.ErrStatus(dest=dest, line=line, col=col)
            raise SyntaxError(f"unknown err:{op}")

        if kw == "struct":
            self._adv()
            self._expect(T.COLON)
            name = self._expect(T.IDENT).value
            fields = []
            self._skip_nl()
            while True:
                t = self._t()
                if t.kind == T.IDENT and t.value.lower() == "end":
                    self._adv()
                    self._expect(T.COLON)
                    endwhat = self._expect(T.IDENT).value.lower()
                    if endwhat != "struct":
                        raise SyntaxError(f"expected end:struct, got end:{endwhat}")
                    break
                if t.kind == T.EOF:
                    raise SyntaxError("unclosed struct")
                # field: name : size  or  name : i8/i16/i32/i64
                fname = self._expect(T.IDENT).value
                self._expect(T.COLON)
                size_tok = self._t()
                if size_tok.kind == T.IDENT:
                    szmap = {"i8": 1, "u8": 1, "i16": 2, "u16": 2, "i32": 4, "u32": 4, "i64": 8, "u64": 8, "ptr": 8}
                    sname = self._adv().value.lower()
                    if sname not in szmap:
                        raise SyntaxError(f"unknown field type {sname}")
                    fsize = szmap[sname]
                elif size_tok.kind == T.NUMBER:
                    fsize = int(self._adv().value, 0)
                else:
                    raise SyntaxError("expected field size or type")
                fields.append((fname, fsize))
                self._skip_nl()
            return A.StructDef(name=name, fields=fields, line=line, col=col)

        if kw == "fn":
            self._adv()
            self._expect(T.COLON)
            name = self._expect(T.IDENT).value
            args = []
            while self._t().kind == T.IDENT:
                args.append(self._adv().value)
            body = []
            locals_ = []
            self._skip_nl()
            while True:
                t = self._t()
                if t.kind == T.IDENT and t.value.lower() == "end":
                    self._adv()
                    self._expect(T.COLON)
                    endwhat = self._expect(T.IDENT).value.lower()
                    if endwhat != "fn":
                        raise SyntaxError(f"expected end:fn, got end:{endwhat}")
                    break
                if t.kind == T.EOF:
                    raise SyntaxError("unclosed fn")
                stmt = self._statement()
                if isinstance(stmt, A.LocalDecl):
                    locals_.append((stmt.name, stmt.size))
                else:
                    body.append(stmt)
                self._skip_nl()
            return A.FnDef(name=name, args=args, body=body, locals_=locals_, line=line, col=col)

        if kw == "local":
            self._adv()
            self._expect(T.COLON)
            name = self._expect(T.IDENT).value
            self._expect(T.EQ)
            size = int(self._expect(T.NUMBER).value, 0)
            return A.LocalDecl(name=name, size=size, line=line, col=col)

        if kw == "ret":
            self._adv()
            val = None
            if self._t().kind not in (T.NEWLINE, T.EOF):
                val = self._operand()
            if val is not None:
                return A.RetVal(value=val, line=line, col=col)
            return A.Ret(line=line, col=col)

        if kw == "kernel":
            self._adv()
            self._expect(T.COLON)
            op = self._expect(T.IDENT).value.lower()
            return self._kernel(op, line, col)

        raise SyntaxError(f"{self.filename}:{line}:{col}: unknown statement '{kw}'")

    def _cpu(self, op: str, line: int, col: int) -> A.Node:
        unary = {"not", "neg", "inc", "dec"}
        binary = {"set", "add", "sub", "mul", "div", "mod", "and", "or", "xor", "shl", "shr", "sar", "sal", "rol", "ror", "rcl", "rcr"}
        if op == "movsxd":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._expect(T.IDENT).value
            return A.CpuMovsxd(dest=dest, src=src, line=line, col=col)
        if op == "imul3":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._expect(T.IDENT).value
            if self._match(T.COMMA):
                pass
            imm = int(self._expect(T.NUMBER).value, 0)
            return A.CpuImul3(dest=dest, src=src, imm=imm, line=line, col=col)
        if op in ("ldmxcsr", "stmxcsr"):
            base = self._expect(T.IDENT).value
            return A.CpuMxcsr(op="ld" if op.startswith("ld") else "st", base=base, line=line, col=col)
        if op in ("fxsave", "fxrstor"):
            base = self._expect(T.IDENT).value
            return A.CpuFx(op="save" if "save" in op else "restore", base=base, line=line, col=col)
        if op == "xgetbv":
            return A.CpuXgetbv(line=line, col=col)
        if op in ("rdfsbase", "rdgsbase", "wrfsbase", "wrgsbase"):
            reg = self._expect(T.IDENT).value
            return A.CpuFsGs(op=op, reg=reg, line=line, col=col)
        if op in ("sldt", "str", "smsw", "swapgs", "rdmsr", "wrmsr", "rdpmc", "clts", "wbinvd", "sysret", "sysenter", "sysexit"):
            reg = "reg1"
            if self._t().kind == T.IDENT:
                reg = self._adv().value
            return A.CpuPrivOp(op=op, reg=reg, line=line, col=col)
        if op == "movzx":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._expect(T.IDENT).value
            width = 8
            if self._match(T.COMMA):
                width = int(self._expect(T.NUMBER).value, 0)
            return A.CpuMovzx(dest=dest, src=src, width=width, line=line, col=col)
        if op == "movsx":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._expect(T.IDENT).value
            width = 8
            if self._match(T.COMMA):
                width = int(self._expect(T.NUMBER).value, 0)
            return A.CpuMovsx(dest=dest, src=src, width=width, line=line, col=col)
        if op in ("btimm", "btsimm", "btrimm", "btcimm"):
            base = self._expect(T.IDENT).value
            if self._match(T.COMMA):
                pass
            imm = int(self._expect(T.NUMBER).value, 0)
            return A.CpuBitImm(op=op.replace("imm",""), base=base, imm=imm, line=line, col=col)
        if op == "shldimm":
            dest = self._expect(T.IDENT).value
            if self._match(T.COMMA):
                pass
            src = self._expect(T.IDENT).value
            if self._match(T.COMMA):
                pass
            imm = int(self._expect(T.NUMBER).value, 0)
            return A.CpuShldImm(dest=dest, src=src, imm=imm, line=line, col=col)
        if op == "shrdimm":
            dest = self._expect(T.IDENT).value
            if self._match(T.COMMA):
                pass
            src = self._expect(T.IDENT).value
            if self._match(T.COMMA):
                pass
            imm = int(self._expect(T.NUMBER).value, 0)
            return A.CpuShrdImm(dest=dest, src=src, imm=imm, line=line, col=col)
        if op == "nopl":
            return A.CpuNopLong(line=line, col=col)
        if op == "enter":
            size = int(self._expect(T.NUMBER).value, 0)
            nesting = 0
            if self._match(T.COMMA):
                nesting = int(self._expect(T.NUMBER).value, 0)
            return A.CpuEnter(size=size, nesting=nesting, line=line, col=col)
        if op == "pext":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._expect(T.IDENT).value
            if self._match(T.COMMA):
                pass
            mask = self._expect(T.IDENT).value
            return A.CpuPext(dest=dest, src=src, mask=mask, line=line, col=col)
        if op == "pdep":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._expect(T.IDENT).value
            if self._match(T.COMMA):
                pass
            mask = self._expect(T.IDENT).value
            return A.CpuPdep(dest=dest, src=src, mask=mask, line=line, col=col)
        if op == "mulx":
            hi = self._expect(T.IDENT).value
            if self._match(T.COMMA):
                pass
            lo = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._expect(T.IDENT).value
            return A.CpuMulx(dest_hi=hi, dest_lo=lo, src=src, line=line, col=col)
        if op == "cmpxchg":
            dest = self._expect(T.IDENT).value
            if self._match(T.COMMA):
                pass
            src = self._expect(T.IDENT).value
            return A.CpuCmpxchg(dest=dest, src=src, line=line, col=col)
        if op == "prefetch":
            kind = self._expect(T.IDENT).value.lower()
            base = self._expect(T.IDENT).value
            return A.CpuPrefetch(kind=kind, base=base, line=line, col=col)
        if op == "clflush":
            base = self._expect(T.IDENT).value
            return A.CpuClflush(base=base, line=line, col=col)
        if op in ("cbw", "cwde", "cwd"):
            return A.CpuFlagOp(op=op, line=line, col=col)
        if op == "shlx":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._expect(T.IDENT).value
            if self._match(T.COMMA):
                pass
            cnt = self._expect(T.IDENT).value
            return A.CpuShlx(dest=dest, src=src, cnt=cnt, line=line, col=col)
        if op == "shrx":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._expect(T.IDENT).value
            if self._match(T.COMMA):
                pass
            cnt = self._expect(T.IDENT).value
            return A.CpuShrx(dest=dest, src=src, cnt=cnt, line=line, col=col)
        if op == "sarx":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._expect(T.IDENT).value
            if self._match(T.COMMA):
                pass
            cnt = self._expect(T.IDENT).value
            return A.CpuSarx(dest=dest, src=src, cnt=cnt, line=line, col=col)
        if op == "rorx":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._expect(T.IDENT).value
            if self._match(T.COMMA):
                pass
            imm = int(self._expect(T.NUMBER).value, 0)
            return A.CpuRorx(dest=dest, src=src, imm=imm, line=line, col=col)
        if op == "bextr":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._expect(T.IDENT).value
            if self._match(T.COMMA):
                pass
            ctrl = self._expect(T.IDENT).value
            return A.CpuBextr(dest=dest, src=src, ctrl=ctrl, line=line, col=col)
        if op == "blsi":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._expect(T.IDENT).value
            return A.CpuBlsi(dest=dest, src=src, line=line, col=col)
        if op == "blsr":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._expect(T.IDENT).value
            return A.CpuBlsr(dest=dest, src=src, line=line, col=col)
        if op == "blsmsk":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._expect(T.IDENT).value
            return A.CpuBlsmsk(dest=dest, src=src, line=line, col=col)
        if op == "adcx":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._expect(T.IDENT).value
            return A.CpuAdcx(dest=dest, src=src, line=line, col=col)
        if op == "adox":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._expect(T.IDENT).value
            return A.CpuAdox(dest=dest, src=src, line=line, col=col)
        if op == "crc32":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._expect(T.IDENT).value
            return A.CpuCrc32(dest=dest, src=src, line=line, col=col)
        if op == "rdrand":
            dest = self._expect(T.IDENT).value
            return A.CpuRdrand(dest=dest, line=line, col=col)
        if op == "rdseed":
            dest = self._expect(T.IDENT).value
            return A.CpuRdseed(dest=dest, line=line, col=col)
        if op == "adc":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._expect(T.IDENT).value
            return A.CpuAdc(dest=dest, src=src, line=line, col=col)
        if op == "sbb":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._expect(T.IDENT).value
            return A.CpuSbb(dest=dest, src=src, line=line, col=col)
        if op == "bswap":
            dest = self._expect(T.IDENT).value
            return A.CpuBswap(dest=dest, line=line, col=col)
        if op in ("clc", "stc", "cmc", "cld", "std", "pause", "cqo", "cdq", "leave", "cdqe", "pushfq", "popfq", "rdtscp", "lfence", "sfence", "mfence", "endbr64"):
            return A.CpuFlagOp(op=op, line=line, col=col)
        if op in ("mulu", "divu"):
            src = self._expect(T.IDENT).value
            return A.CpuMulDiv1(op="mul" if op == "mulu" else "div", src=src, line=line, col=col)
        if op == "testimm":
            dest = self._expect(T.IDENT).value
            if self._match(T.COMMA):
                pass
            imm = int(self._expect(T.NUMBER).value, 0)
            return A.CpuTestImm(dest=dest, imm=imm, line=line, col=col)
        if op in ("bts", "btr", "btc"):
            base = self._expect(T.IDENT).value
            if self._match(T.COMMA):
                pass
            off = self._expect(T.IDENT).value
            return A.CpuBitOp(op=op, base=base, offset=off, line=line, col=col)
        if op == "popcnt":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._expect(T.IDENT).value
            return A.CpuPopcnt(dest=dest, src=src, line=line, col=col)
        if op == "lzcnt":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._expect(T.IDENT).value
            return A.CpuLzcnt(dest=dest, src=src, line=line, col=col)
        if op == "tzcnt":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._expect(T.IDENT).value
            return A.CpuTzcnt(dest=dest, src=src, line=line, col=col)
        if op == "shld":
            dest = self._expect(T.IDENT).value
            if self._t().kind == T.COMMA:
                self._adv()
            src = self._expect(T.IDENT).value
            return A.CpuShld(dest=dest, src=src, line=line, col=col)
        if op == "shrd":
            dest = self._expect(T.IDENT).value
            if self._t().kind == T.COMMA:
                self._adv()
            src = self._expect(T.IDENT).value
            return A.CpuShrd(dest=dest, src=src, line=line, col=col)
        if op == "imulimm":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            imm = int(self._expect(T.NUMBER).value, 0)
            return A.CpuImulImm(dest=dest, imm=imm, line=line, col=col)
        if op == "andn":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src1 = self._expect(T.IDENT).value
            if self._t().kind == T.COMMA:
                self._adv()
            src2 = self._expect(T.IDENT).value
            return A.CpuAndn(dest=dest, src1=src1, src2=src2, line=line, col=col)
        if op == "bzhi":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._expect(T.IDENT).value
            if self._t().kind == T.COMMA:
                self._adv()
            ctrl = self._expect(T.IDENT).value
            return A.CpuBzhi(dest=dest, src=src, ctrl=ctrl, line=line, col=col)
        if op == "cmpxchg16b":
            self._expect(T.LBRACK)
            base = self._operand()
            off = 0
            if self._match(T.PLUS):
                off = int(self._expect(T.NUMBER).value, 0)
            self._expect(T.RBRACK)
            return A.CpuCmpxchg16b(base=base, offset=off, line=line, col=col)
        if op == "cmovmem":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            self._expect(T.LBRACK)
            base = self._operand()
            off = 0
            if self._match(T.PLUS):
                off = int(self._expect(T.NUMBER).value, 0)
            self._expect(T.RBRACK)
            if self._t().kind == T.COMMA:
                self._adv()
            cond = self._expect(T.IDENT).value.lower()
            return A.CpuCmovMem(dest=dest, base=base, offset=off, cond=cond, line=line, col=col)
        if op == "xchg":
            a = self._expect(T.IDENT).value
            if self._t().kind == T.COMMA:
                self._adv()
            b = self._expect(T.IDENT).value
            return A.CpuXchg(a=a, b=b, line=line, col=col)
        if op == "xadd":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._expect(T.IDENT).value
            return A.CpuXadd(dest=dest, src=src, line=line, col=col)
        if op in ("bsf", "bsr"):
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._operand()
            return A.CpuBitScan(op=op, dest=dest, src=src, line=line, col=col)
        if op == "bt":
            base = self._expect(T.IDENT).value
            if self._t().kind == T.COMMA:
                self._adv()
            off = self._operand()
            return A.CpuBt(base=base, offset=off, line=line, col=col)
        if op in unary:
            dest = self._expect(T.IDENT).value
            return A.CpuUnary(op=op, dest=dest, line=line, col=col)
        if op == "cmov":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._operand()
            if self._t().kind == T.COMMA:
                self._adv()
            cond = self._expect(T.IDENT).value.lower()
            return A.CpuCmov(dest=dest, src=src, cond=cond, line=line, col=col)
        if op == "lea":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            self._expect(T.LBRACK)
            # [rip + label] or [abs imm] or normal
            if self._t().kind == T.IDENT and self._t().value.lower() == "rip":
                self._adv()
                self._expect(T.PLUS)
                lab = self._expect(T.IDENT).value
                self._expect(T.RBRACK)
                return A.CpuLeaRip(dest=dest, label=lab, line=line, col=col)
            if self._t().kind == T.IDENT and self._t().value.lower() == "abs":
                self._adv()
                addr = int(self._expect(T.NUMBER).value, 0)
                self._expect(T.RBRACK)
                return A.CpuLeaAbs(dest=dest, addr=addr, line=line, col=col)
            base = self._primary()
            index = None
            scale = 1
            offset = 0
            while self._match(T.PLUS):
                if self._t().kind == T.NUMBER:
                    offset += int(self._adv().value, 0)
                    continue
                opnd = self._primary()
                if isinstance(opnd, A.BinExpr) and opnd.op == "*" and isinstance(opnd.left, A.Reg) and isinstance(opnd.right, A.Number):
                    index = opnd.left
                    scale = opnd.right.value
                    if scale not in (1, 2, 4, 8):
                        raise SyntaxError("lea scale must be 1,2,4,8")
                elif isinstance(opnd, A.Reg):
                    if self._match(T.STAR):
                        scale = int(self._expect(T.NUMBER).value, 0)
                        if scale not in (1, 2, 4, 8):
                            raise SyntaxError("lea scale must be 1,2,4,8")
                        index = opnd
                    else:
                        index = opnd
                else:
                    raise SyntaxError("bad lea address form")
            self._expect(T.RBRACK)
            return A.CpuLea(dest=dest, base=base, index=index, scale=scale, offset=offset, line=line, col=col)
        if op == "test":
            left = self._operand()
            if self._t().kind == T.COMMA:
                self._adv()
            right = self._operand()
            return A.CpuTest(left=left, right=right, line=line, col=col)
        if op in ("movzx", "movsx"):
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            # optional width: 8 or 16 as number, or infer from ram load size later
            size = 8
            if self._t().kind == T.NUMBER:
                size = int(self._adv().value, 0)
                if size not in (8, 16):
                    raise SyntaxError("movzx/movsx size must be 8 or 16")
            src = self._operand()
            return A.CpuMovExt(op=op, dest=dest, src=src, size=size, line=line, col=col)
        if op not in binary:
            raise SyntaxError(f"unknown cpu:{op}")
        dest = self._expect(T.IDENT).value
        self._expect(T.EQ)
        val = self._operand()
        return A.CpuBin(op=op, dest=dest, value=val, line=line, col=col)

    def _data(self, what: str, line: int, col: int) -> A.Node:
        if what == "align":
            n = int(self._expect(T.NUMBER).value, 0)
            if n < 1 or (n & (n - 1)) != 0:
                raise SyntaxError("data:align must be power of 2")
            return A.DataAlign(align=n, line=line, col=col)
        name = self._expect(T.IDENT).value
        self._expect(T.EQ)
        if what == "alloc":
            if self._t().kind == T.NUMBER:
                size = int(self._adv().value, 0)
            else:
                # struct name or expression — store as Ident, resolve size in collect_data
                size = self._expect(T.IDENT).value  # type: ignore
            return A.DataAlloc(name=name, size=size, line=line, col=col)
        if what == "const":
            if self._t().kind == T.STRING:
                s = self._adv().value
                return A.DataConst(name=name, value=A.String(value=s, line=line, col=col), line=line, col=col)
            num = int(self._expect(T.NUMBER).value, 0)
            return A.DataConst(name=name, value=A.Number(value=num, line=line, col=col), line=line, col=col)
        if what == "bytes":
            vals = []
            while self._t().kind not in (T.NEWLINE, T.EOF):
                if self._match(T.COMMA):
                    continue
                if self._t().kind == T.NUMBER:
                    vals.append(int(self._adv().value, 0) & 0xFF)
                elif self._t().kind == T.IDENT:
                    vals.append(int(self._adv().value, 16) & 0xFF)
                else:
                    break
            if not vals:
                raise SyntaxError("data:bytes needs at least one byte")
            return A.DataBytes(name=name, values=vals, line=line, col=col)
        raise SyntaxError(f"unknown data:{what}")

    def _ram(self, what: str, line: int, col: int) -> A.Node:
        size = 64
        if what.startswith("read"):
            if what == "read8":
                size = 8
            elif what == "read16":
                size = 16
            elif what == "read32":
                size = 32
            elif what in ("read", "read64"):
                size = 64
            else:
                raise SyntaxError(f"unknown ram:{what}")
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            base, off, index, scale = self._mem_addr()
            return A.MemLoad(dest=dest, base=base, offset=off, size=size, index=index, scale=scale, line=line, col=col)
        if what.startswith("write"):
            if what == "write8":
                size = 8
            elif what == "write16":
                size = 16
            elif what == "write32":
                size = 32
            elif what in ("write", "write64"):
                size = 64
            else:
                raise SyntaxError(f"unknown ram:{what}")
            base, off, index, scale = self._mem_addr()
            self._expect(T.EQ)
            val = self._operand()
            return A.MemStore(base=base, offset=off, value=val, size=size, index=index, scale=scale, line=line, col=col)
        raise SyntaxError(f"unknown ram:{what}")

    def _mem_addr(self):
        """Parse [base] | [base+disp] | [base+index] | [base+index*scale] |
        [base+index*scale+disp] | [base+disp+index*scale] simplified left-to-right.
        Returns (base, offset, index_or_None, scale).
        """
        self._expect(T.LBRACK)
        base = self._primary()  # do not consume + here; offsets handled below
        off = 0
        index = None
        scale = 1
        while self._match(T.PLUS):
            if self._t().kind == T.NUMBER:
                off += int(self._adv().value, 0)
            else:
                opnd = self._operand()
                # index * scale parsed as BinExpr by expression grammar
                if isinstance(opnd, A.BinExpr) and opnd.op == "*" and isinstance(opnd.left, A.Reg) and isinstance(opnd.right, A.Number):
                    index = opnd.left
                    scale = opnd.right.value
                    if scale not in (1, 2, 4, 8):
                        raise SyntaxError("scale must be 1,2,4,8")
                elif isinstance(opnd, A.Reg):
                    index = opnd
                    if self._match(T.STAR):
                        scale = int(self._expect(T.NUMBER).value, 0)
                        if scale not in (1, 2, 4, 8):
                            raise SyntaxError("scale must be 1,2,4,8")
                elif isinstance(opnd, (A.StructFieldRef, A.BinExpr, A.Number, A.Ident)):
                    if isinstance(off, int) and isinstance(opnd, A.Number):
                        off += opnd.value
                    elif isinstance(off, int) and off == 0:
                        off = opnd
                    else:
                        left = A.Number(value=off) if isinstance(off, int) else off
                        off = A.BinExpr(op="+", left=left, right=opnd)
                else:
                    index = opnd
        self._expect(T.RBRACK)
        return base, off, index, scale

    def _syscall(self, line: int, col: int) -> A.Node:
        # sys:call <num|name> args...
        if self._t().kind == T.NUMBER:
            num: Any = A.Number(value=int(self._adv().value, 0), line=line, col=col)
        else:
            num = self._expect(T.IDENT).value
        args = []
        while self._t().kind not in (T.NEWLINE, T.EOF):
            if self._match(T.COMMA):
                continue
            args.append(self._operand())
        return A.SysCall(num=num, args=args, line=line, col=col)

    def _stack(self, what: str, line: int, col: int) -> A.Node:
        if what == "push":
            val = self._operand()
            return A.StackPush(value=val, line=line, col=col)
        if what == "pop":
            dest = self._expect(T.IDENT).value
            return A.StackPop(dest=dest, line=line, col=col)
        raise SyntaxError(f"unknown stack:{what}")


    def _blast(self, op: str, line: int, col: int) -> A.Node:
        if op == "fill":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            byte_val = self._operand()
            self._expect(T.COMMA)
            length = self._operand()
            return A.BlastFill(dest=dest, byte_val=byte_val, length=length, line=line, col=col)
        if op in ("rep_fill", "repfill"):
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            byte_val = self._operand()
            self._expect(T.COMMA)
            length = self._operand()
            return A.BlastRepFill(dest=dest, byte_val=byte_val, length=length, line=line, col=col)
        if op in ("rep_copy", "repcopy"):
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._operand()
            self._expect(T.COMMA)
            length = self._operand()
            return A.BlastRepCopy(dest=dest, src=src, length=length, line=line, col=col)
        if op == "copy":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._operand()
            self._expect(T.COMMA)
            length = self._operand()
            return A.BlastCopy(dest=dest, src=src, length=length, line=line, col=col)
        raise SyntaxError(f"unknown blast:{op}")

    def _wire(self, op: str, line: int, col: int) -> A.Node:
        if op == "len":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._operand()
            return A.WireLen(dest=dest, src=src, line=line, col=col)
        if op == "cmp":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            left = self._operand()
            self._expect(T.COMMA)
            right = self._operand()
            return A.WireCmp(dest=dest, left=left, right=right, line=line, col=col)
        if op == "copy":
            dest = self._operand()
            self._expect(T.EQ)
            src = self._operand()
            return A.WireCopy(dest=dest, src=src, line=line, col=col)
        if op == "emit":
            src = self._operand()
            length = None
            if self._t().kind not in (T.NEWLINE, T.EOF):
                if self._match(T.COMMA):
                    pass
                length = self._operand()
            return A.WireEmit(src=src, length=length, line=line, col=col)
        raise SyntaxError(f"unknown wire:{op}")

    def _operand(self) -> Any:
        """Full expression: add/sub of mul/div of primaries, with parentheses.
        Precedence: ( )  >  *  >  + -
        """
        return self._expr_add()

    def _expr_add(self) -> Any:
        node = self._expr_mul()
        while self._t().kind in (T.PLUS, T.MINUS):
            op = "+" if self._t().kind == T.PLUS else "-"
            self._adv()
            right = self._expr_mul()
            node = A.BinExpr(op=op, left=node, right=right,
                             line=getattr(node, "line", 1), col=getattr(node, "col", 1))
        return node

    def _expr_mul(self) -> Any:
        node = self._primary()
        while self._t().kind == T.STAR:
            self._adv()
            right = self._primary()
            node = A.BinExpr(op="*", left=node, right=right,
                             line=getattr(node, "line", 1), col=getattr(node, "col", 1))
        return node

    def _primary(self) -> Any:
        t = self._t()
        if t.kind == T.LPAREN:
            self._adv()
            node = self._expr_add()
            self._expect(T.RPAREN, "closing )")
            return node
        if t.kind == T.NUMBER:
            self._adv()
            return A.Number(value=int(t.value, 0), line=t.line, col=t.col)
        if t.kind == T.STRING:
            self._adv()
            return A.String(value=t.value, line=t.line, col=t.col)
        if t.kind == T.IDENT:
            self._adv()
            name = t.value
            from .regs import is_reg_name
            if is_reg_name(name):
                return A.Reg(name=name, line=t.line, col=t.col)
            if self._match(T.DOT):
                field = self._expect(T.IDENT).value
                return A.StructFieldRef(struct=name, field=field, line=t.line, col=t.col)
            return A.Ident(name=name, line=t.line, col=t.col)
        raise SyntaxError(f"{self.filename}:{t.line}:{t.col}: expected operand")

    def _cell(self, op: str, line: int, col: int) -> A.Node:
        if op == "map":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            size = self._operand()
            prot = flags = None
            if self._match(T.COMMA):
                prot = self._operand()
                if self._match(T.COMMA):
                    flags = self._operand()
            return A.CellMap(dest=dest, size=size, prot=prot, flags=flags, line=line, col=col)
        if op == "mapfile":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            size = self._operand()
            self._match(T.COMMA)
            fd = self._operand()
            offset = prot = None
            if self._match(T.COMMA):
                offset = self._operand()
                if self._match(T.COMMA):
                    prot = self._operand()
            return A.CellMapFile(dest=dest, size=size, fd=fd, offset=offset, prot=prot, line=line, col=col)
        if op == "free":
            ptr = self._operand()
            if self._t().kind == T.COMMA:
                self._adv()
            size = self._operand()
            return A.CellFree(ptr=ptr, size=size, line=line, col=col)
        if op == "protect":
            ptr = self._operand()
            if self._match(T.COMMA):
                pass
            size = self._operand()
            if self._match(T.COMMA):
                pass
            prot = self._operand()
            return A.CellProtect(ptr=ptr, size=size, prot=prot, line=line, col=col)
        raise SyntaxError(f"unknown cell:{op}")

    def _gate(self, op: str, line: int, col: int) -> A.Node:
        if op == "cas":
            addr = self._expect(T.IDENT).value
            self._expect(T.EQ)
            exp = self._expect(T.IDENT).value
            if self._t().kind == T.COMMA:
                self._adv()
            des = self._expect(T.IDENT).value
            return A.GateCas(addr=addr, expected=exp, desired=des, line=line, col=col)
        if op == "spin":
            addr = self._expect(T.IDENT).value
            return A.GateSpin(addr=addr, line=line, col=col)
        if op == "fence":
            kind = "mfence"
            if self._t().kind == T.IDENT:
                kind = self._adv().value.lower()
            return A.GateFence(kind=kind, line=line, col=col)
        raise SyntaxError(f"unknown gate:{op}")

    def _pulse(self, op: str, line: int, col: int) -> A.Node:
        if op == "sleep":
            ns = self._operand()
            return A.PulseSleep(ns=ns, line=line, col=col)
        if op == "now":
            dest = self._expect(T.IDENT).value
            return A.PulseNow(dest=dest, line=line, col=col)
        raise SyntaxError(f"unknown pulse:{op}")

    def _chip(self, op: str, line: int, col: int) -> A.Node:
        if op == "ticks":
            dest = self._expect(T.IDENT).value
            return A.ChipTicks(dest=dest, line=line, col=col)
        if op == "id":
            leaf = self._operand()
            # optional: dest regs a,b,c,d — default reg1..reg4
            da, db, dc, dd = "reg1", "reg2", "reg3", "reg4"
            if self._t().kind == T.IDENT:
                da = self._adv().value
                if self._t().kind == T.COMMA:
                    self._adv()
                if self._t().kind == T.IDENT:
                    db = self._adv().value
                    if self._t().kind == T.COMMA:
                        self._adv()
                    if self._t().kind == T.IDENT:
                        dc = self._adv().value
                        if self._t().kind == T.COMMA:
                            self._adv()
                        if self._t().kind == T.IDENT:
                            dd = self._adv().value
            return A.ChipId(leaf=leaf, dest_a=da, dest_b=db, dest_c=dc, dest_d=dd, line=line, col=col)
        if op == "cli":
            return A.ChipCli(line=line, col=col)
        if op == "sti":
            return A.ChipSti(line=line, col=col)
        if op == "halt" or op == "hlt":
            return A.ChipHalt(line=line, col=col)
        if op == "serial_init":
            return A.ChipSerialInit(line=line, col=col)
        if op == "serial_putc":
            val = self._operand()
            return A.ChipSerialPutc(value=val, line=line, col=col)
        if op == "lidt":
            base = self._expect(T.IDENT).value
            return A.ChipLidt(base=base, line=line, col=col)
        if op == "lgdt":
            base = self._expect(T.IDENT).value
            return A.ChipLgdt(base=base, line=line, col=col)
        if op == "kbd_poll":
            dest = self._expect(T.IDENT).value
            return A.ChipKbdPoll(dest=dest, line=line, col=col)
        if op == "int":
            n = int(self._expect(T.NUMBER).value, 0)
            return A.ChipInt(vec=n & 0xFF, line=line, col=col)
        if op == "pit_init":
            div = 11932
            if self._t().kind == T.NUMBER:
                div = int(self._adv().value, 0) & 0xFFFF
                if div == 0:
                    div = 1
            return A.ChipPitInit(divisor=div, line=line, col=col)
        if op == "pic_remap":
            return A.ChipPicRemap(line=line, col=col)
        raise SyntaxError(f"unknown chip:{op}")


    def _kernel(self, op: str, line: int, col: int) -> A.Node:
        if op == "heap_init":
            size = int(self._expect(T.NUMBER).value, 0)
            return A.KernelHeapInit(size=size, line=line, col=col)
        if op == "heap_alloc":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            size = self._operand()
            return A.KernelHeapAlloc(dest=dest, size=size, line=line, col=col)
        if op == "ctx_save":
            dest = self._expect(T.IDENT).value
            return A.KernelCtxSave(dest=dest, line=line, col=col)
        if op == "ctx_load":
            src = self._expect(T.IDENT).value
            return A.KernelCtxLoad(src=src, line=line, col=col)
        if op == "idt_install":
            return A.KernelIdtInstall(line=line, col=col)
        if op == "coop_switch":
            a = self._expect(T.IDENT).value
            self._expect(T.COMMA)
            b = self._expect(T.IDENT).value
            return A.KernelCoopSwitch(save=a, load=b, line=line, col=col)
        if op == "printk_str":
            src = self._operand()
            return A.KernelPrintkStr(src=src, line=line, col=col)
        if op == "panic":
            return A.KernelPanic(line=line, col=col)
        if op == "tick_install":
            return A.KernelTickInstall(line=line, col=col)
        if op == "tick_read":
            dest = self._expect(T.IDENT).value
            return A.KernelTickRead(dest=dest, line=line, col=col)
        if op == "ramfs_init":
            return A.KernelRamfsInit(line=line, col=col)
        if op == "ramfs_put":
            name = self._operand()
            self._expect(T.COMMA)
            data = self._operand()
            self._expect(T.COMMA)
            length = self._operand()
            return A.KernelRamfsPut(name=name, data=data, length=length, line=line, col=col)
        if op == "ramfs_get":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            name = self._operand()
            return A.KernelRamfsGet(dest=dest, name=name, line=line, col=col)
        if op == "net_init":
            return A.KernelNetInit(line=line, col=col)
        if op == "net_poll":
            dest = self._expect(T.IDENT).value
            return A.KernelNetPoll(dest=dest, line=line, col=col)
        if op == "cs_ring":
            dest = self._expect(T.IDENT).value
            return A.KernelCsRing(dest=dest, line=line, col=col)
        if op == "enter_user":
            entry = self._operand()
            self._expect(T.COMMA)
            stack = self._operand()
            return A.KernelEnterUser(entry=entry, stack=stack, line=line, col=col)
        if op == "pf_install":
            return A.KernelPfInstall(line=line, col=col)
        if op == "net_allow_port":
            n = int(self._expect(T.NUMBER).value, 0)
            return A.KernelNetAllowPort(port=n & 63, line=line, col=col)
        if op == "net_check_port":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            port = self._operand()
            return A.KernelNetCheckPort(dest=dest, port=port, line=line, col=col)
        if op == "preempt_arm":
            ctx = self._expect(T.IDENT).value
            return A.KernelPreemptArm(ctx=ctx, line=line, col=col)
        if op == "syscall_init":
            return A.KernelSyscallInit(line=line, col=col)
        if op == "sysret":
            return A.KernelSysret(line=line, col=col)
        if op == "nic_bar":
            addr = self._operand()
            return A.KernelNicBar(addr=addr, line=line, col=col)
        if op == "nic_reg_read":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            off = self._operand()
            return A.KernelNicRegRead(dest=dest, offset=off, line=line, col=col)
        if op == "nic_reg_write":
            off = self._operand()
            self._expect(T.EQ)
            val = self._operand()
            return A.KernelNicRegWrite(offset=off, value=val, line=line, col=col)
        if op == "irq_full_save_on":
            return A.KernelIrqFullSave(line=line, col=col)
        if op == "syscall_table_init":
            return A.KernelSyscallTableInit(line=line, col=col)
        if op == "syscall_register":
            nr = int(self._expect(T.NUMBER).value, 0) & 63
            self._expect(T.COMMA)
            if self._t().kind == T.LABEL:
                h = self._adv().value
            else:
                h = self._expect(T.IDENT).value.lstrip("~")
            return A.KernelSyscallRegister(nr=nr, handler=h, line=line, col=col)
        if op == "nmi_install":
            return A.KernelNmiInstall(line=line, col=col)
        if op == "dma_ring_init":
            n = 16
            if self._t().kind == T.NUMBER:
                n = int(self._adv().value, 0)
            # force power of 2
            if n < 2:
                n = 2
            if n & (n - 1):
                n = 1 << n.bit_length()
            return A.KernelDmaRingInit(slots=n, line=line, col=col)
        if op == "dma_ring_push":
            addr = self._operand()
            self._expect(T.COMMA)
            ln = self._operand()
            return A.KernelDmaRingPush(addr=addr, length=ln, line=line, col=col)
        if op == "dma_ring_pop":
            da = self._expect(T.IDENT).value
            self._expect(T.COMMA)
            dl = self._expect(T.IDENT).value
            return A.KernelDmaRingPop(dest_addr=da, dest_len=dl, line=line, col=col)
        raise SyntaxError(f"unknown kernel:{op}")

    def _port(self, op: str, line: int, col: int) -> A.Node:
        if op == "out":
            port = self._operand()
            self._expect(T.EQ)
            val = self._operand()
            return A.PortOut(port=port, value=val, line=line, col=col)
        if op == "in":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            port = self._operand()
            return A.PortIn(dest=dest, port=port, line=line, col=col)
        raise SyntaxError(f"unknown port:{op}")

    def _vec(self, op: str, line: int, col: int) -> A.Node:
        if op == "load":
            xmm = self._expect(T.IDENT).value
            self._expect(T.EQ)
            self._expect(T.LBRACK)
            base = self._operand()
            off = 0
            if self._match(T.PLUS):
                off = int(self._expect(T.NUMBER).value, 0)
            self._expect(T.RBRACK)
            return A.VecLoad(xmm=xmm, base=base, offset=off, line=line, col=col)
        if op == "store":
            self._expect(T.LBRACK)
            base = self._operand()
            off = 0
            if self._match(T.PLUS):
                off = int(self._expect(T.NUMBER).value, 0)
            self._expect(T.RBRACK)
            self._expect(T.EQ)
            xmm = self._expect(T.IDENT).value
            return A.VecStore(base=base, offset=off, xmm=xmm, line=line, col=col)
        if op in ("addps", "subps", "mulps", "divps"):
            dst = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._expect(T.IDENT).value
            return A.VecBin(op=op, dst=dst, src=src, line=line, col=col)
        if op in ("vaddps", "vsubps", "vmulps", "vdivps"):
            dst = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._expect(T.IDENT).value
            return A.VecVBin(op=op, dst=dst, src=src, line=line, col=col)
        if op == "vshufps":
            dst = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._expect(T.IDENT).value
            if self._t().kind == T.COMMA:
                self._adv()
            imm = int(self._expect(T.NUMBER).value, 0)
            return A.VecVBin(op="vshufps", dst=dst, src=src, imm=imm, line=line, col=col)
        if op == "vbroadcastss":
            dst = self._expect(T.IDENT).value
            self._expect(T.EQ)
            src = self._expect(T.IDENT).value
            return A.VecVBin(op="vbroadcastss", dst=dst, src=src, line=line, col=col)
        if op == "vload":
            ymm = self._expect(T.IDENT).value
            self._expect(T.EQ)
            self._expect(T.LBRACK)
            base = self._operand()
            off = 0
            if self._match(T.PLUS):
                off = int(self._expect(T.NUMBER).value, 0)
            self._expect(T.RBRACK)
            return A.VecVLoad(ymm=ymm, base=base, offset=off, line=line, col=col)
        if op == "vstore":
            self._expect(T.LBRACK)
            base = self._operand()
            off = 0
            if self._match(T.PLUS):
                off = int(self._expect(T.NUMBER).value, 0)
            self._expect(T.RBRACK)
            self._expect(T.EQ)
            ymm = self._expect(T.IDENT).value
            return A.VecVStore(base=base, offset=off, ymm=ymm, line=line, col=col)
        raise SyntaxError(f"unknown vec:{op}")

    def _thread(self, op: str, line: int, col: int) -> A.Node:
        if op == "spawn":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            lab = self._expect(T.LABEL).value
            return A.ThreadSpawn(dest=dest, label=lab, line=line, col=col)
        if op == "join_all" or op == "joinall":
            return A.ThreadJoinAll(line=line, col=col)
        if op == "join":
            tid = None
            if self._t().kind not in (T.NEWLINE, T.EOF):
                tid = self._operand()
            return A.ThreadJoin(tid=tid, line=line, col=col)
        if op == "exit":
            code = None
            if self._t().kind not in (T.NEWLINE, T.EOF):
                code = self._operand()
            return A.ThreadExit(code=code, line=line, col=col)
        raise SyntaxError(f"unknown thread:{op}")

    def _net(self, op: str, line: int, col: int) -> A.Node:
        if op == "poll":
            fds = self._operand()
            self._match(T.COMMA)
            nfds = self._operand()
            self._match(T.COMMA)
            timeout = self._operand()
            return A.NetPoll(fds=fds, nfds=nfds, timeout=timeout, line=line, col=col)
        if op == "epoll_create":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            flags = self._operand() if self._t().kind not in (T.NEWLINE, T.EOF) else None
            return A.NetEpollCreate(dest=dest, flags=flags, line=line, col=col)
        if op == "epoll_ctl":
            epfd = self._operand()
            self._match(T.COMMA)
            opv = self._operand()
            self._match(T.COMMA)
            fd = self._operand()
            self._match(T.COMMA)
            ev = self._operand()
            return A.NetEpollCtl(epfd=epfd, op=opv, fd=fd, event_ptr=ev, line=line, col=col)
        if op == "epoll_wait":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            epfd = self._operand()
            self._match(T.COMMA)
            events = self._operand()
            self._match(T.COMMA)
            maxevents = self._operand()
            self._match(T.COMMA)
            timeout = self._operand()
            return A.NetEpollWait(dest=dest, epfd=epfd, events=events, maxevents=maxevents, timeout=timeout, line=line, col=col)
        if op == "socket":
            dest = self._expect(T.IDENT).value
            self._expect(T.EQ)
            domain = self._operand()
            if self._t().kind == T.COMMA:
                self._adv()
            type_ = self._operand()
            if self._t().kind == T.COMMA:
                self._adv()
            proto = self._operand()
            return A.NetSocket(dest=dest, domain=domain, type_=type_, protocol=proto, line=line, col=col)
        if op == "connect":
            sock = self._operand()
            if self._t().kind == T.COMMA:
                self._adv()
            addr = self._operand()
            if self._t().kind == T.COMMA:
                self._adv()
            alen = self._operand()
            return A.NetConnect(sock=sock, addr=addr, addrlen=alen, line=line, col=col)
        if op == "send":
            sock = self._operand()
            if self._t().kind == T.COMMA:
                self._adv()
            buf = self._operand()
            if self._t().kind == T.COMMA:
                self._adv()
            ln = self._operand()
            return A.NetSend(sock=sock, buf=buf, length=ln, line=line, col=col)
        if op == "recv":
            sock = self._operand()
            if self._t().kind == T.COMMA:
                self._adv()
            buf = self._operand()
            if self._t().kind == T.COMMA:
                self._adv()
            ln = self._operand()
            return A.NetRecv(sock=sock, buf=buf, length=ln, line=line, col=col)
        if op == "close":
            sock = self._operand()
            return A.NetClose(sock=sock, line=line, col=col)
        raise SyntaxError(f"unknown net:{op}")
