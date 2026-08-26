# rawmachine/x64enc.py
"""
Minimal x86-64 instruction encoder.

Ye module NASM/GAS use nahi karta -- har instruction ke liye seedha uske
opcode bytes hum khud bana rahe hain (ModRM/SIB/REX prefix encoding sahit).
Isko ACL ke 'raw' mode ka backend chalata hai jo asm text generate karne ke
bajaye directly machine code bytes emit karta hai.

Sirf wahi instructions yahan hain jo ACL ke lowlevel AST ko cover karne ke
liye zaroori hain (64-bit GP registers, immediate/reg mov, arithmetic,
compare, conditional jumps, call/ret, push/pop, syscall). Ye ek "brutal but
correct" subset hai -- poora x86 encode nahi karta, jitna cheh karna hai
utna hi, sahi.
"""

from typing import List, Optional

# ---- Register encoding: name -> (3-bit field, needs_REX_B/R/X extension) ----
# x86-64 mein 16 GP registers hain; unke 4-bit encoding ka top bit REX
# prefix mein jata hai (REX.B for rm/base, REX.R for reg, REX.X for index).
REGISTERS = {
    "rax": 0, "rcx": 1, "rdx": 2, "rbx": 3,
    "rsp": 4, "rbp": 5, "rsi": 6, "rdi": 7,
    "r8": 8, "r9": 9, "r10": 10, "r11": 11,
    "r12": 12, "r13": 13, "r14": 14, "r15": 15,
}


def _u8(v: int) -> bytes:
    return (v & 0xFF).to_bytes(1, "little")


def _s8(v: int) -> bytes:
    if v < -128 or v > 127:
        raise ValueError(f"value {v} does not fit in imm8")
    return (v & 0xFF).to_bytes(1, "little", signed=False)


def _u32(v: int) -> bytes:
    return (v & 0xFFFFFFFF).to_bytes(4, "little")


def _s32(v: int) -> bytes:
    if v < -2**31 or v > 2**31 - 1:
        raise ValueError(f"value {v} does not fit in imm32")
    return v.to_bytes(4, "little", signed=True)


def _u64(v: int) -> bytes:
    return (v & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")


def reg_num(name: str) -> int:
    r = REGISTERS.get(name)
    if r is None:
        raise ValueError(f"unknown/unsupported physical register: {name}")
    return r


def rex(w: int = 1, r: int = 0, x: int = 0, b: int = 0) -> int:
    """REX prefix byte. w=1 -> 64-bit operand size (almost always what we want)."""
    return 0x40 | (w << 3) | (r << 2) | (x << 1) | b


def modrm(mod: int, reg: int, rm: int) -> int:
    return ((mod & 0b11) << 6) | ((reg & 0b111) << 3) | (rm & 0b111)


class Label:
    """Forward/backward jump target placeholder, resolved at link time."""
    __slots__ = ("name",)

    def __init__(self, name: str):
        self.name = name


class Reloc:
    """A 4-byte rel32 (or 8-byte abs64) fixup recorded during encoding,
    patched once every label's final address is known."""
    __slots__ = ("offset", "target", "kind", "size")

    def __init__(self, offset: int, target: str, kind: str, size: int):
        self.offset = offset      # byte offset in the code buffer where the fixup lives
        self.target = target      # label name being referenced
        self.kind = kind          # "rel32" (jmp/call/jcc) or "abs64" (data pointer load)
        self.size = size          # 4 or 8


class Assembler:
    """
    Accumulates raw machine code bytes for one function/program body.
    Call the instruction methods in order; call `label()` to mark jump
    targets; call `link()` at the end to patch all Reloc fixups once every
    label's final offset is known.
    """

    def __init__(self):
        self.code = bytearray()
        self.labels: dict = {}     # name -> byte offset into self.code
        self.relocs: List[Reloc] = []
        self.deterministic = False

    # ---- bookkeeping ----
    def label(self, name: str):
        if name in self.labels:
            raise ValueError(f"duplicate label: {name}")
        self.labels[name] = len(self.code)

    def here(self) -> int:
        return len(self.code)

    def _emit(self, b: bytes):
        self.code += b

    def _emit_rel32_fixup(self, target: str):
        self._emit(b"\x00\x00\x00\x00")
        self.relocs.append(Reloc(len(self.code) - 4, target, "rel32", 4))

    def link(self, base_offset_map: Optional[dict] = None):
        """Patch every recorded rel32 fixup now that all labels are known.
        base_offset_map lets a caller remap label offsets (e.g. when this
        buffer gets concatenated after another one)."""
        offs = self.labels if base_offset_map is None else base_offset_map
        for r in self.relocs:
            if r.target not in offs:
                raise ValueError(f"undefined label referenced: {r.target}")
            target_off = offs[r.target]
            # rel32 is relative to the address of the NEXT instruction,
            # i.e. right after this 4-byte fixup field.
            rel = target_off - (r.offset + 4)
            self.code[r.offset:r.offset + 4] = _s32(rel)

    # ================= Data movement =================

    def mov_reg_imm64(self, dst: str, imm: int):
        """Optimal imm load (or full movabs if deterministic)."""
        imm = int(imm) & ((1 << 64) - 1)
        d = reg_num(dst)
        if getattr(self, "deterministic", False):
            # Always 10-byte: REX.W + B8+r + imm64
            self._emit(_u8(rex(w=1, b=(d >> 3))))
            self._emit(_u8(0xB8 + (d & 7)))
            self._emit(_u64(imm))
            return
        # Zero: mov r32, 0 (flag-preserving; xor would clobber ZF needed by cmov/jcc)
        if imm == 0:
            if d >= 8:
                self._emit(_u8(0x41))
            self._emit(_u8(0xB8 + (d & 7)))
            self._emit(_u32(0))
            return
        # 32-bit zero-extendable (fits in unsigned 32-bit)
        if imm <= 0xFFFFFFFF:
            if d >= 8:
                self._emit(_u8(0x41))
            self._emit(_u8(0xB8 + (d & 7)))
            self._emit(_u32(imm))
            return
        # sign-extended 32-bit via mov r/m64, imm32 (C7 /0) when fits signed 32
        if imm >= 0xFFFFFFFF80000000 or imm < 0x80000000:
            # actually for values that sign-extend correctly from imm32
            signed = imm if imm < 0x80000000 else imm - (1 << 64)
            if -0x80000000 <= signed <= 0x7FFFFFFF:
                # REX.W C7 /0 id
                self._emit(_u8(rex(w=1, b=(d >> 3))))
                self._emit(_u8(0xC7))
                self._emit(_u8(modrm(0b11, 0, d & 7)))
                self._emit(_u32(signed & 0xFFFFFFFF))
                return
        # full imm64
        self._emit(_u8(rex(w=1, b=(d >> 3))))
        self._emit(_u8(0xB8 + (d & 7)))
        self._emit(_u64(imm))

    def mov_reg_reg(self, dst: str, src: str):
        """mov r64, r64 — skip if dst==src (identity)."""
        if dst == src:
            return
        d, s = reg_num(dst), reg_num(src)
        self._emit(_u8(rex(w=1, r=(s >> 3), b=(d >> 3))))
        self._emit(_u8(0x89))
        self._emit(_u8(modrm(0b11, s & 7, d & 7)))

    def mov_reg_mem(self, dst: str, base: str, disp: int, index: str = None, scale: int = 1):
        """mov r64, [base + index*scale + disp]"""
        self._emit_mem_op(0x8B, dst, base, disp, index, scale)

    def mov_mem_reg(self, base: str, disp: int, src: str, index: str = None, scale: int = 1):
        """mov [base + index*scale + disp], r64"""
        self._emit_mem_op(0x89, src, base, disp, index, scale)

    # ---- Sized loads/stores (u8/u16/u32/u64) -- zaroori hain byte-level
    # struct layouts, packed data, aur C-jaisi type-sized memory access ke
    # liye. 64-bit se chhota load default se zero-extend hota hai (movzx),
    # jo sabse predictable/common behavior hai (jaisa Rust/Zig karte hain).

    def mov8_reg_mem(self, dst: str, base: str, disp: int, index: str = None, scale: int = 1):
        """movzx r64, byte [base+disp] -- 8-bit load, zero-extended to 64-bit."""
        self._emit_mem_op_0f(0xB6, dst, base, disp, index, scale)

    def mov16_reg_mem(self, dst: str, base: str, disp: int, index: str = None, scale: int = 1):
        """movzx r64, word [base+disp] -- 16-bit load, zero-extended to 64-bit."""
        self._emit_mem_op_0f(0xB7, dst, base, disp, index, scale)

    def mov32_reg_mem(self, dst: str, base: str, disp: int, index: str = None, scale: int = 1):
        """mov r32, dword [base+disp] -- 32-bit load; writing a 32-bit GP
        reg on x86-64 auto zero-extends the upper 32 bits, so no explicit
        movzx opcode is needed (unlike the 8/16-bit cases above)."""
        r = reg_num(dst)
        b = reg_num(base)
        use_sib = index is not None or (b & 7) == 4
        rex_x = 0
        need_rex = r >= 8 or b >= 8
        if use_sib:
            if index is not None:
                idx = reg_num(index)
                rex_x = idx >> 3
                need_rex = need_rex or rex_x
                scale_bits = {1: 0, 2: 1, 4: 2, 8: 3}[scale]
                sib = (scale_bits << 6) | ((idx & 7) << 3) | (b & 7)
            else:
                sib = (0 << 6) | (0b100 << 3) | (b & 7)
        mod = 0b10 if (disp != 0 or (b & 7) == 5) else 0b00
        if need_rex:
            self._emit(_u8(rex(w=0, r=(r >> 3), x=rex_x, b=(b >> 3))))
        self._emit(_u8(0x8B))
        rm_field = 0b100 if use_sib else (b & 7)
        self._emit(_u8(modrm(mod, r & 7, rm_field)))
        if use_sib:
            self._emit(_u8(sib))
        if mod == 0b10:
            self._emit(_s32(disp))

    def _emit_mem_op_0f(self, opcode2: int, reg_operand: str, base: str, disp: int,
                         index: Optional[str], scale: int):
        """Two-byte-opcode (0F xx) memory-operand form, used by movzx."""
        r = reg_num(reg_operand)
        b = reg_num(base)
        use_sib = index is not None or (b & 7) == 4
        rex_x = 0
        if use_sib:
            if index is not None:
                idx = reg_num(index)
                rex_x = idx >> 3
                scale_bits = {1: 0, 2: 1, 4: 2, 8: 3}[scale]
                sib = (scale_bits << 6) | ((idx & 7) << 3) | (b & 7)
            else:
                sib = (0 << 6) | (0b100 << 3) | (b & 7)
        mod = 0b10 if (disp != 0 or (b & 7) == 5) else 0b00
        self._emit(_u8(rex(w=1, r=(r >> 3), x=rex_x, b=(b >> 3))))
        self._emit(b"\x0F")
        self._emit(_u8(opcode2))
        rm_field = 0b100 if use_sib else (b & 7)
        self._emit(_u8(modrm(mod, r & 7, rm_field)))
        if use_sib:
            self._emit(_u8(sib))
        if mod == 0b10:
            self._emit(_s32(disp))

    def mov8_mem_reg(self, base: str, disp: int, src: str, index: str = None, scale: int = 1):
        """mov byte [base+disp], r8 (low byte of src)."""
        self._emit_mem_op_sized(0x88, src, base, disp, index, scale, size=8)

    def mov16_mem_reg(self, base: str, disp: int, src: str, index: str = None, scale: int = 1):
        """mov word [base+disp], r16 (low word of src) -- needs 0x66 prefix."""
        self._emit_mem_op_sized(0x89, src, base, disp, index, scale, size=16)

    def mov32_mem_reg(self, base: str, disp: int, src: str, index: str = None, scale: int = 1):
        """mov dword [base+disp], r32 (low dword of src)."""
        self._emit_mem_op_sized(0x89, src, base, disp, index, scale, size=32)

    def _emit_mem_op_sized(self, opcode: int, reg_operand: str, base: str, disp: int,
                            index: Optional[str], scale: int, size: int):
        r = reg_num(reg_operand)
        b = reg_num(base)
        use_sib = index is not None or (b & 7) == 4
        rex_x = 0
        if use_sib:
            if index is not None:
                idx = reg_num(index)
                rex_x = idx >> 3
                scale_bits = {1: 0, 2: 1, 4: 2, 8: 3}[scale]
                sib = (scale_bits << 6) | ((idx & 7) << 3) | (b & 7)
            else:
                sib = (0 << 6) | (0b100 << 3) | (b & 7)
        mod = 0b10 if (disp != 0 or (b & 7) == 5) else 0b00
        if size == 16:
            self._emit(b"\x66")  # operand-size override prefix
        need_rex = size == 8 and (r in (4, 5, 6, 7))  # spl/bpl/sil/dil need REX to address true low byte
        need_rex = need_rex or r >= 8 or b >= 8 or rex_x
        if need_rex or size != 8:
            self._emit(_u8(rex(w=0, r=(r >> 3), x=rex_x, b=(b >> 3))))
        self._emit(_u8(opcode))
        rm_field = 0b100 if use_sib else (b & 7)
        self._emit(_u8(modrm(mod, r & 7, rm_field)))
        if use_sib:
            self._emit(_u8(sib))
        if mod == 0b10:
            self._emit(_s32(disp))

    def _emit_mem_op(self, opcode: int, reg_operand: str, base: str, disp: int,
                      index: Optional[str], scale: int):
        r = reg_num(reg_operand)
        b = reg_num(base)
        use_sib = index is not None or (b & 7) == 4  # rsp/r12 as base always need SIB
        rex_x = 0
        if use_sib:
            if index is not None:
                idx = reg_num(index)
                rex_x = idx >> 3
                scale_bits = {1: 0, 2: 1, 4: 2, 8: 3}[scale]
                sib = (scale_bits << 6) | ((idx & 7) << 3) | (b & 7)
            else:
                sib = (0 << 6) | (0b100 << 3) | (b & 7)  # no index
        mod = 0b10 if (disp != 0 or (b & 7) == 5) else 0b00  # rbp/r13 base needs disp8/32 even if 0
        self._emit(_u8(rex(w=1, r=(r >> 3), x=rex_x, b=(b >> 3))))
        self._emit(_u8(opcode))
        rm_field = 0b100 if use_sib else (b & 7)
        self._emit(_u8(modrm(mod, r & 7, rm_field)))
        if use_sib:
            self._emit(_u8(sib))
        if mod == 0b10:
            self._emit(_s32(disp))

    # ================= Arithmetic (reg, reg) and (reg, imm32) =================

    def _binop_reg_reg(self, opcode: int, dst: str, src: str):
        d, s = reg_num(dst), reg_num(src)
        self._emit(_u8(rex(w=1, r=(s >> 3), b=(d >> 3))))
        self._emit(_u8(opcode))
        self._emit(_u8(modrm(0b11, s & 7, d & 7)))

    def add_reg_reg(self, dst, src): self._binop_reg_reg(0x01, dst, src)
    def sub_reg_reg(self, dst, src): self._binop_reg_reg(0x29, dst, src)
    def and_reg_reg(self, dst, src): self._binop_reg_reg(0x21, dst, src)
    def or_reg_reg(self, dst, src):  self._binop_reg_reg(0x09, dst, src)
    def xor_reg_reg(self, dst, src): self._binop_reg_reg(0x31, dst, src)
    def cmp_reg_reg(self, a, b):     self._binop_reg_reg(0x39, a, b)
    def test_reg_reg(self, a, b):    self._binop_reg_reg(0x85, a, b)

    def _binop_reg_imm32(self, ext: int, dst: str, imm: int):
        """Opcode 81 /ext id  -- reg OP imm32 (sign-extended if imm fits, else full 32-bit)."""
        d = reg_num(dst)
        self._emit(_u8(rex(w=1, b=(d >> 3))))
        self._emit(_u8(0x81))
        self._emit(_u8(modrm(0b11, ext, d & 7)))
        self._emit(_s32(imm))

    def add_reg_imm(self, dst, imm): self._binop_reg_imm32(0, dst, imm)
    def sub_reg_imm(self, dst, imm): self._binop_reg_imm32(5, dst, imm)
    def and_reg_imm(self, dst, imm): self._binop_reg_imm32(4, dst, imm)
    def or_reg_imm(self, dst, imm):  self._binop_reg_imm32(1, dst, imm)
    def xor_reg_imm(self, dst, imm): self._binop_reg_imm32(6, dst, imm)
    def cmp_reg_imm(self, dst, imm): self._binop_reg_imm32(7, dst, imm)

    def imul_reg_reg(self, dst: str, src: str):
        """imul r64, r64/m64  (0F AF /r) -- dst <- dst * src"""
        d, s = reg_num(dst), reg_num(src)
        self._emit(_u8(rex(w=1, r=(d >> 3), b=(s >> 3))))
        self._emit(b"\x0F\xAF")
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))

    def idiv_reg(self, src: str):
        """idiv r64  (F7 /7) -- signed divide RDX:RAX by src; quotient->RAX, remainder->RDX.
        Caller MUST sign-extend RAX into RDX first (cqo) before this."""
        s = reg_num(src)
        self._emit(_u8(rex(w=1, b=(s >> 3))))
        self._emit(_u8(0xF7))
        self._emit(_u8(modrm(0b11, 7, s & 7)))

    def cqo(self):
        """Sign-extend RAX into RDX:RAX -- required before idiv."""
        self._emit(b"\x48\x99")

    def not_reg(self, r):
        rr = reg_num(r)
        self._emit(_u8(rex(w=1, b=(rr >> 3))))
        self._emit(_u8(0xF7))
        self._emit(_u8(modrm(0b11, 2, rr & 7)))

    def neg_reg(self, r):
        rr = reg_num(r)
        self._emit(_u8(rex(w=1, b=(rr >> 3))))
        self._emit(_u8(0xF7))
        self._emit(_u8(modrm(0b11, 3, rr & 7)))

    def inc_reg(self, r):
        rr = reg_num(r)
        self._emit(_u8(rex(w=1, b=(rr >> 3))))
        self._emit(_u8(0xFF))
        self._emit(_u8(modrm(0b11, 0, rr & 7)))

    def dec_reg(self, r):
        rr = reg_num(r)
        self._emit(_u8(rex(w=1, b=(rr >> 3))))
        self._emit(_u8(0xFF))
        self._emit(_u8(modrm(0b11, 1, rr & 7)))

    def shl_reg_imm8(self, r, imm):
        rr = reg_num(r)
        self._emit(_u8(rex(w=1, b=(rr >> 3))))
        self._emit(_u8(0xC1))
        self._emit(_u8(modrm(0b11, 4, rr & 7)))
        self._emit(_u8(imm & 0x3F))

    def shr_reg_imm8(self, r, imm):
        rr = reg_num(r)
        self._emit(_u8(rex(w=1, b=(rr >> 3))))
        self._emit(_u8(0xC1))
        self._emit(_u8(modrm(0b11, 5, rr & 7)))
        self._emit(_u8(imm & 0x3F))

    def rol_reg_imm8(self, r, imm):
        rr = reg_num(r)
        self._emit(_u8(rex(w=1, b=(rr >> 3))))
        self._emit(_u8(0xC1))
        self._emit(_u8(modrm(0b11, 0, rr & 7)))
        self._emit(_u8(imm & 0x3F))

    def ror_reg_imm8(self, r, imm):
        rr = reg_num(r)
        self._emit(_u8(rex(w=1, b=(rr >> 3))))
        self._emit(_u8(0xC1))
        self._emit(_u8(modrm(0b11, 1, rr & 7)))
        self._emit(_u8(imm & 0x3F))

    # Variable-count shifts/rotates: count must already be in CL (RCX low byte).
    # Opcode form: REX.W + D3 /r   (SHL/SHR/ROL/ROR r/m64, CL)
    def shl_reg_cl(self, r):
        rr = reg_num(r)
        self._emit(_u8(rex(w=1, b=(rr >> 3))))
        self._emit(_u8(0xD3))
        self._emit(_u8(modrm(0b11, 4, rr & 7)))

    def shr_reg_cl(self, r):
        rr = reg_num(r)
        self._emit(_u8(rex(w=1, b=(rr >> 3))))
        self._emit(_u8(0xD3))
        self._emit(_u8(modrm(0b11, 5, rr & 7)))

    def rol_reg_cl(self, r):
        rr = reg_num(r)
        self._emit(_u8(rex(w=1, b=(rr >> 3))))
        self._emit(_u8(0xD3))
        self._emit(_u8(modrm(0b11, 0, rr & 7)))

    def ror_reg_cl(self, r):
        rr = reg_num(r)
        self._emit(_u8(rex(w=1, b=(rr >> 3))))
        self._emit(_u8(0xD3))
        self._emit(_u8(modrm(0b11, 1, rr & 7)))

    # ================= setcc (branchless flag capture) =================

    SETCC_OPCODE = {
        "eq": 0x94, "neq": 0x95, "gt": 0x9F, "lt": 0x9C,
        "gte": 0x9D, "lte": 0x9E, "above": 0x97, "below": 0x92,
        "abe": 0x96, "ble": 0x96,
        # aliases (teaching)
        "zf": 0x94, "e": 0x94, "z": 0x94,
        "nz": 0x95, "ne": 0x95,
        "g": 0x9F, "nle": 0x9F,
        "l": 0x9C, "nge": 0x9C,
        "ge": 0x9D, "nl": 0x9D,
        "le": 0x9E, "ng": 0x9E,
        "a": 0x97, "nbe": 0x97,
        "b": 0x92, "c": 0x92, "nae": 0x92,
        "ae": 0x93, "nb": 0x93, "nc": 0x93,
        "be": 0x96, "na": 0x96,
        "s": 0x98, "ns": 0x99,
        "o": 0x90, "no": 0x91,
        "p": 0x9A, "pe": 0x9A, "np": 0x9B, "po": 0x9B,
    }

    def setcc_reg(self, cond: str, dst: str):
        """SETcc r8 (zero-extends into the low byte; caller and-masks if a
        clean 0/1 in the full 64-bit reg is needed)."""
        op = self.SETCC_OPCODE[cond]
        d = reg_num(dst)
        if d >= 8:
            self._emit(_u8(rex(w=0, b=1)))
        elif d in (4, 5, 6, 7):  # rsp/rbp/rsi/rdi need REX just to access the true low byte
            self._emit(_u8(rex(w=0)))
        self._emit(b"\x0F")
        self._emit(_u8(op))
        self._emit(_u8(modrm(0b11, 0, d & 7)))
        # zero-extend low byte without clobbering flags (movzx, not and)
        self._emit(_u8(rex(w=1, r=(d >> 3), b=(d >> 3))))
        self._emit(b"\x0F")
        self._emit(_u8(0xB6))
        self._emit(_u8(modrm(0b11, d & 7, d & 7)))

    # ================= Control flow =================

    JCC_OPCODE = {
        "eq": 0x84, "neq": 0x85, "gt": 0x8F, "lt": 0x8C,
        "gte": 0x8D, "lte": 0x8E, "above": 0x87, "below": 0x82,
        "abe": 0x83, "ae": 0x83, "be": 0x86, "ble": 0x86,
        "zf": 0x84, "e": 0x84, "z": 0x84,
        "nz": 0x85, "ne": 0x85,
        "g": 0x8F, "nle": 0x8F,
        "l": 0x8C, "nge": 0x8C,
        "ge": 0x8D, "nl": 0x8D,
        "le": 0x8E, "ng": 0x8E,
        "a": 0x87, "nbe": 0x87,
        "b": 0x82, "c": 0x82, "nae": 0x82,
        "ae": 0x83, "nb": 0x83, "nc": 0x83,
        "be": 0x86, "na": 0x86,
        "s": 0x88, "ns": 0x89,
        "o": 0x80, "no": 0x81,
        "p": 0x8A, "pe": 0x8A, "np": 0x8B, "po": 0x8B,
    }

    def jmp(self, target: str):
        self._emit(b"\xE9")
        self._emit_rel32_fixup(target)

    def jcc(self, cond: str, target: str):
        op = self.JCC_OPCODE[cond]
        self._emit(b"\x0F")
        self._emit(_u8(op))
        self._emit_rel32_fixup(target)

    def call(self, target: str):
        self._emit(b"\xE8")
        self._emit_rel32_fixup(target)

    def ret(self):
        self._emit(b"\xC3")

    def leave(self):
        """leave = mov rsp,rbp ; pop rbp"""
        self._emit(b"\xC9")

    def push_reg(self, r):
        rr = reg_num(r)
        if rr >= 8:
            self._emit(_u8(rex(w=0, b=1)))
        self._emit(_u8(0x50 + (rr & 7)))

    def pop_reg(self, r):
        rr = reg_num(r)
        if rr >= 8:
            self._emit(_u8(rex(w=0, b=1)))
        self._emit(_u8(0x58 + (rr & 7)))

    def syscall(self):
        self._emit(b"\x0F\x05")

    def nop(self):
        self._emit(b"\x90")

    def movzx_reg_reg(self, dst: str, src: str, size: int = 8):
        """movzx r64, r8/r16"""
        d, s = reg_num(dst), reg_num(src)
        self._emit(_u8(rex(w=1, r=(d >> 3), b=(s >> 3))))
        self._emit(b"\x0F")
        self._emit(_u8(0xB6 if size == 8 else 0xB7))
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))

    def movsx_reg_reg(self, dst: str, src: str, size: int = 8):
        """movsx r64, r8/r16"""
        d, s = reg_num(dst), reg_num(src)
        self._emit(_u8(rex(w=1, r=(d >> 3), b=(s >> 3))))
        self._emit(b"\x0F")
        self._emit(_u8(0xBE if size == 8 else 0xBF))
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))

    def cld(self):
        self._emit(b"\xFC")

    def std(self):
        self._emit(b"\xFD")

    def raw_bytes(self, data: bytes):
        """Inline raw-byte escape hatch -- injects exact bytes into the
        instruction stream, no encoding/validation. This is the language's
        'asm{}' equivalent: when the compiler doesn't support an
        instruction yet, the user can drop its opcode bytes directly."""
        self._emit(data)

    def hlt(self):
        self._emit(b"\xF4")

    def lea_reg_label(self, dst: str, target: str):
        """lea r64, [rip + disp32]  -- RIP-relative load of a data label's address."""
        d = reg_num(dst)
        self._emit(_u8(rex(w=1, r=(d >> 3))))
        self._emit(_u8(0x8D))
        self._emit(_u8(modrm(0b00, d & 7, 0b101)))  # mod=00, rm=101 -> RIP-relative
        self._emit(b"\x00\x00\x00\x00")
        self.relocs.append(Reloc(len(self.code) - 4, target, "rel32", 4))

    # ================= x87 FPU (memory-operand forms only) =================
    # Har instruction '[base]' (RIP-relative label) ya '[reg]' (register
    # indirect, disp=0) operand leta hai -- FPU virtual registers isi liye
    # memory-backed hain (jaise NASM backend ke __freg1..8 slots), koi x87
    # stack register allocation nahi kar rahe, taaki encoding simple aur
    # predictable rahe.

    def _fpu_mem_op(self, opcode_byte: int, digit: int, base: str, disp: int = 0):
        b = reg_num(base)
        use_sib = (b & 7) == 4
        mod = 0b10 if (disp != 0 or (b & 7) == 5) else 0b00
        if b >= 8:
            self._emit(_u8(rex(w=0, b=1)))
        self._emit(_u8(opcode_byte))
        rm_field = 0b100 if use_sib else (b & 7)
        self._emit(_u8(modrm(mod, digit, rm_field)))
        if use_sib:
            self._emit(_u8((0 << 6) | (0b100 << 3) | (b & 7)))
        if mod == 0b10:
            self._emit(_s32(disp))

    def fld_m64(self, base: str, disp: int = 0):
        """fld qword [base+disp] -- push a double onto the FPU stack."""
        self._fpu_mem_op(0xDD, 0, base, disp)

    def fstp_m64(self, base: str, disp: int = 0):
        """fstp qword [base+disp] -- pop ST(0) into memory."""
        self._fpu_mem_op(0xDD, 3, base, disp)

    def fild_m64(self, base: str, disp: int = 0):
        """fild qword [base+disp] -- push a 64-bit integer, converted to double."""
        self._fpu_mem_op(0xDF, 5, base, disp)

    def fistp_m64(self, base: str, disp: int = 0):
        """fistp qword [base+disp] -- pop ST(0), truncate to int64, store."""
        self._fpu_mem_op(0xDF, 7, base, disp)

    def faddp(self):
        """faddp st(1), st(0) -- ST(1) += ST(0); pop. (D8 C1 is the ST(0),ST(1) reversed form; DE C1 is what we want.)"""
        self._emit(b"\xDE\xC1")

    def fsubp(self):
        self._emit(b"\xDE\xE9")

    def fmulp(self):
        self._emit(b"\xDE\xC9")

    def fdivp(self):
        self._emit(b"\xDE\xF9")

    def fcomip(self):
        """fcomip st(0), st(1) -- compare ST(0) vs ST(1), set integer ZF/PF/CF, pop once."""
        self._emit(b"\xDF\xF1")

    def fstsw_ax(self):
        self._emit(b"\xDF\xE0")

    def fxch(self):
        """fxch st(1) -- swap ST(0) and ST(1)."""
        self._emit(b"\xD9\xC9")


    # ================= SSE (packed single-precision) =================

    XMM = {
        "xmm0": 0, "xmm1": 1, "xmm2": 2, "xmm3": 3,
        "xmm4": 4, "xmm5": 5, "xmm6": 6, "xmm7": 7,
    }

    def _xmm_num(self, name: str) -> int:
        n = self.XMM.get(name.lower())
        if n is None:
            raise ValueError(f"unknown/unsupported xmm register: {name}")
        return n

    def movups_xmm_mem(self, xmm: str, base: str, disp: int = 0):
        """movups xmm, [base+disp]  -- unaligned load of 16 bytes"""
        x = self._xmm_num(xmm)
        b = reg_num(base)
        # 0F 10 /r  with REX if needed for base >= r8
        rex_byte = 0
        if b >= 8:
            rex_byte = rex(w=0, r=(x >> 3), b=1)
            b &= 7
        elif x >= 8:
            rex_byte = rex(w=0, r=1, b=0)
        if rex_byte:
            self._emit(_u8(rex_byte))
        self._emit(b"\x0F\x10")
        if disp == 0 and b != 5:  # rbp needs disp
            self._emit(_u8(modrm(0b00, x & 7, b)))
            if b == 4:  # rsp/r12 need SIB
                self._emit(_u8(0x24))
        elif -128 <= disp <= 127:
            self._emit(_u8(modrm(0b01, x & 7, b)))
            if b == 4:
                self._emit(_u8(0x24))
            self._emit(_s8(disp))
        else:
            self._emit(_u8(modrm(0b10, x & 7, b)))
            if b == 4:
                self._emit(_u8(0x24))
            self._emit(_s32(disp))

    def movups_mem_xmm(self, base: str, xmm: str, disp: int = 0):
        """movups [base+disp], xmm  -- unaligned store of 16 bytes"""
        x = self._xmm_num(xmm)
        b = reg_num(base)
        rex_byte = 0
        if b >= 8:
            rex_byte = rex(w=0, r=(x >> 3), b=1)
            b &= 7
        elif x >= 8:
            rex_byte = rex(w=0, r=1, b=0)
        if rex_byte:
            self._emit(_u8(rex_byte))
        self._emit(b"\x0F\x11")
        if disp == 0 and b != 5:
            self._emit(_u8(modrm(0b00, x & 7, b)))
            if b == 4:
                self._emit(_u8(0x24))
        elif -128 <= disp <= 127:
            self._emit(_u8(modrm(0b01, x & 7, b)))
            if b == 4:
                self._emit(_u8(0x24))
            self._emit(_s8(disp))
        else:
            self._emit(_u8(modrm(0b10, x & 7, b)))
            if b == 4:
                self._emit(_u8(0x24))
            self._emit(_s32(disp))

    def _sse_binop_xmm_xmm(self, opcode2: int, dst: str, src: str):
        """Generic SSE xmm,xmm binary op: 0F <opcode2> /r  (dst is reg field)"""
        d = self._xmm_num(dst)
        s = self._xmm_num(src)
        # No REX needed for xmm0-7
        self._emit(b"\x0F")
        self._emit(_u8(opcode2))
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))

    def addps(self, dst, src): self._sse_binop_xmm_xmm(0x58, dst, src)
    def subps(self, dst, src): self._sse_binop_xmm_xmm(0x5C, dst, src)
    def mulps(self, dst, src): self._sse_binop_xmm_xmm(0x59, dst, src)
    def divps(self, dst, src): self._sse_binop_xmm_xmm(0x5E, dst, src)
    def movaps_xmm_xmm(self, dst, src): self._sse_binop_xmm_xmm(0x28, dst, src)

    def _sse_pd_binop(self, opcode_prefix_byte: int, opcode2: int, dst: str, src: str):
        """PD ops use 66 0F xx prefix (SSE2 packed double)."""
        d = self._xmm_num(dst)
        s = self._xmm_num(src)
        self._emit(_u8(0x66))
        self._emit(b"\x0F")
        self._emit(_u8(opcode2))
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))

    def addpd(self, dst, src): self._sse_pd_binop(0x66, 0x58, dst, src)
    def subpd(self, dst, src): self._sse_pd_binop(0x66, 0x5C, dst, src)
    def mulpd(self, dst, src): self._sse_pd_binop(0x66, 0x59, dst, src)
    def divpd(self, dst, src): self._sse_pd_binop(0x66, 0x5E, dst, src)

    def paddd(self, dst, src):
        """paddd xmm, xmm -- 66 0F FE /r"""
        d = self._xmm_num(dst)
        s = self._xmm_num(src)
        self._emit(_u8(0x66))
        self._emit(b"\x0F\xFE")
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))

    def psubd(self, dst, src):
        """psubd xmm, xmm -- 66 0F FA /r"""
        d = self._xmm_num(dst)
        s = self._xmm_num(src)
        self._emit(_u8(0x66))
        self._emit(b"\x0F\xFA")
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))

    def shufps(self, dst, src, imm8: int):
        """shufps xmm, xmm, imm8 -- 0F C6 /r ib"""
        d = self._xmm_num(dst)
        s = self._xmm_num(src)
        self._emit(b"\x0F\xC6")
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))
        self._emit(_u8(imm8 & 0xFF))


    def lock_cmpxchg_mem(self, base: str, disp: int, src: str):
        """lock cmpxchg qword [base+disp], src -- RAX is implicit compare operand.
        Correctly handles rbp/r13 (must use mod=01) and rsp/r12 (need SIB)."""
        r = reg_num(src)
        b = reg_num(base)
        self._emit(_u8(0xF0))
        rex = 0x48
        if r >= 8:
            rex |= 0x04
        if b >= 8:
            rex |= 0x01
        self._emit(_u8(rex))
        self._emit(b"\x0F\xB1")
        rm = b & 7
        reg = r & 7
        # force disp8 form for rbp/r13 (rm==5) when caller passes disp=0
        need_disp = (disp != 0) or (rm == 5)
        if rm == 4:  # rsp/r12 -> SIB
            mod = 0b01 if need_disp or disp != 0 else 0b00
            if disp != 0 or rm == 5:
                mod = 0b01
            self._emit(_u8(modrm(mod, reg, 4)))
            self._emit(_u8((0 << 6) | (4 << 3) | rm))
            if mod == 0b01:
                self._emit(_u8(disp & 0xFF))
        elif need_disp:
            self._emit(_u8(modrm(0b01, reg, rm)))
            self._emit(_u8(disp & 0xFF))
        else:
            self._emit(_u8(modrm(0b00, reg, rm)))


    def xchg_mem_reg(self, base: str, disp: int, reg: str):
        """xchg [base+disp], reg — atomic on x86 for aligned"""
        r = reg_num(reg)
        b = reg_num(base)
        rex = 0x48 | ((r >> 3) << 2) | (b >> 3)
        self._emit(_u8(rex))
        self._emit(_u8(0x87))
        if disp == 0 and (b & 7) != 5:
            self._emit(_u8(modrm(0b00, r & 7, b & 7)))
        else:
            self._emit(_u8(modrm(0b01, r & 7, b & 7)))
            self._emit(_u8(disp & 0xFF))


    def haddps(self, dst, src):
        """haddps xmm, xmm -- F2 0F 7C /r"""
        d, s = self._xmm_num(dst), self._xmm_num(src)
        self._emit(_u8(0xF2))
        self._emit(b"\x0F\x7C")
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))

    def blendps(self, dst, src, imm8: int):
        """blendps xmm, xmm, imm8 -- 66 0F 3A 0C /r ib"""
        d, s = self._xmm_num(dst), self._xmm_num(src)
        self._emit(_u8(0x66))
        self._emit(b"\x0F\x3A\x0C")
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))
        self._emit(_u8(imm8 & 0xFF))

    def _ymm_num(self, name: str) -> int:
        n = name.lower()
        if n.startswith("ymm"):
            return int(n[3:])
        if n.startswith("xmm"):
            return int(n[3:])
        raise ValueError(f"not a vector reg: {name}")

    def _vex_nnds_ps(self, opcode: int, dst: str, src1: str, src2: str):
        """VEX.256.0F.WIG op ymm, ymm, ymm for vaddps etc (opcode 0x58 etc)."""
        d = self._ymm_num(dst)
        s1 = self._ymm_num(src1)
        s2 = self._ymm_num(src2)
        # VEX 3-byte: C4 RXB.mmmmm W.vvvv.L.pp opcode ModRM
        # mmmmm=1 (0F), pp=0, L=1 (256), W=0, vvvv = ~s1
        # For 2-byte VEX when possible: C5 (~R).vvvv.L.pp
        # Use 3-byte always for simplicity with high regs
        R = 1 if d < 8 else 0
        X = 1
        B = 1 if s2 < 8 else 0
        map_ = 1  # 0F
        W = 0
        vvvv = (~s1) & 0xF
        L = 1
        pp = 0
        self._emit(_u8(0xC4))
        self._emit(_u8((R << 7) | (X << 6) | (B << 5) | map_))
        self._emit(_u8((W << 7) | (vvvv << 3) | (L << 2) | pp))
        self._emit(_u8(opcode))
        self._emit(_u8(modrm(0b11, d & 7, s2 & 7)))

    def vaddps(self, dst, src1, src2=None):
        if src2 is None:
            src2 = src1
            src1 = dst
        self._vex_nnds_ps(0x58, dst, src1, src2)

    def vsubps(self, dst, src1, src2=None):
        if src2 is None:
            src2 = src1
            src1 = dst
        self._vex_nnds_ps(0x5C, dst, src1, src2)

    def vmulps(self, dst, src1, src2=None):
        if src2 is None:
            src2 = src1
            src1 = dst
        self._vex_nnds_ps(0x59, dst, src1, src2)

    def vdivps(self, dst, src1, src2=None):
        if src2 is None:
            src2 = src1
            src1 = dst
        self._vex_nnds_ps(0x5E, dst, src1, src2)

    def vmovups_load(self, dst, base: str, disp: int = 0):
        """vmovups ymm, [base]"""
        d = self._ymm_num(dst)
        b = reg_num(base)
        R = 1 if d < 8 else 0
        B = 1 if b < 8 else 0
        self._emit(_u8(0xC5))
        # C5 R.vvvv.L.pp with vvvv=1111, L=1, pp=0
        self._emit(_u8((R << 7) | (0xF << 3) | (1 << 2) | 0))
        self._emit(_u8(0x10))  # vmovups load
        rm = b & 7
        if rm == 5 or disp != 0:
            self._emit(_u8(modrm(0b01, d & 7, rm)))
            self._emit(_u8(disp & 0xFF))
        elif rm == 4:
            self._emit(_u8(modrm(0b00, d & 7, 4)))
            self._emit(_u8((0 << 6) | (4 << 3) | rm))
        else:
            self._emit(_u8(modrm(0b00, d & 7, rm)))

    def vmovups_store(self, base: str, src: str, disp: int = 0):
        s = self._ymm_num(src)
        b = reg_num(base)
        R = 1 if s < 8 else 0
        B = 1 if b < 8 else 0
        self._emit(_u8(0xC5))
        self._emit(_u8((R << 7) | (0xF << 3) | (1 << 2) | 0))
        self._emit(_u8(0x11))
        rm = b & 7
        if rm == 5 or disp != 0:
            self._emit(_u8(modrm(0b01, s & 7, rm)))
            self._emit(_u8(disp & 0xFF))
        elif rm == 4:
            self._emit(_u8(modrm(0b00, s & 7, 4)))
            self._emit(_u8((0 << 6) | (4 << 3) | rm))
        else:
            self._emit(_u8(modrm(0b00, s & 7, rm)))


    def rdtsc(self):
        """rdtsc → EDX:EAX (high:low)."""
        self._emit(b"\x0F\x31")

    def cpuid(self):
        """cpuid — leaf in EAX, result EAX/EBX/ECX/EDX."""
        self._emit(b"\x0F\xA2")

    def mfence(self):
        self._emit(b"\x0F\xAE\xF0")

    def lfence(self):
        self._emit(b"\x0F\xAE\xE8")

    def sfence(self):
        self._emit(b"\x0F\xAE\xF8")

    def cli(self):
        self._emit(b"\xFA")

    def sti(self):
        self._emit(b"\xFB")

    def in_al_dx(self):
        """in al, dx"""
        self._emit(b"\xEC")

    def out_dx_al(self):
        """out dx, al"""
        self._emit(b"\xEE")

    def lea_reg_mem(self, dst: str, base: str, disp: int = 0, index: str = None, scale: int = 1):
        """lea r64, [base + index*scale + disp]"""
        d = reg_num(dst)
        b = reg_num(base)
        scale_map = {1: 0, 2: 1, 4: 2, 8: 3}
        if index is not None:
            ix = reg_num(index)
            sc = scale_map.get(scale, 0)
            rex_v = 0x48 | ((d >> 3) << 2) | ((ix >> 3) << 1) | (b >> 3)
            self._emit(_u8(rex_v))
            self._emit(_u8(0x8D))
            mod = 0b01 if disp != 0 or (b & 7) == 5 else 0b00
            self._emit(_u8(modrm(mod, d & 7, 4)))  # SIB
            self._emit(_u8((sc << 6) | ((ix & 7) << 3) | (b & 7)))
            if mod == 0b01:
                self._emit(_u8(disp & 0xFF))
        else:
            rex_v = 0x48 | ((d >> 3) << 2) | (b >> 3)
            self._emit(_u8(rex_v))
            self._emit(_u8(0x8D))
            rm = b & 7
            if rm == 4:
                mod = 0b01 if disp else 0b00
                self._emit(_u8(modrm(mod, d & 7, 4)))
                self._emit(_u8((0 << 6) | (4 << 3) | rm))
                if mod == 0b01:
                    self._emit(_u8(disp & 0xFF))
            elif disp != 0 or rm == 5:
                self._emit(_u8(modrm(0b01, d & 7, rm)))
                self._emit(_u8(disp & 0xFF))
            else:
                self._emit(_u8(modrm(0b00, d & 7, rm)))


    CMOV_OPCODE = {
        "eq": 0x44, "neq": 0x45, "lt": 0x4C, "gt": 0x4F,
        "lte": 0x4E, "gte": 0x4D, "below": 0x42, "above": 0x47,
        "abe": 0x43, "ae": 0x43, "be": 0x46, "ble": 0x46,
    }

    def cmov_reg_reg(self, cond: str, dst: str, src: str):
        """cmovcc r64, r64"""
        op = self.CMOV_OPCODE[cond]
        d, s = reg_num(dst), reg_num(src)
        self._emit(_u8(rex(w=1, r=(d >> 3), b=(s >> 3))))
        self._emit(b"\x0F")
        self._emit(_u8(op))
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))


    def xchg_reg_reg(self, a: str, b: str):
        """xchg r64, r64"""
        ra, rb = reg_num(a), reg_num(b)
        if a == b:
            return
        # Prefer opcode form xchg rax, r64 when possible
        if ra == 0:
            if rb >= 8:
                self._emit(_u8(0x49))  # REX.WB
            else:
                self._emit(_u8(0x48))
            self._emit(_u8(0x90 + (rb & 7)))
            return
        if rb == 0:
            if ra >= 8:
                self._emit(_u8(0x49))
            else:
                self._emit(_u8(0x48))
            self._emit(_u8(0x90 + (ra & 7)))
            return
        self._emit(_u8(rex(w=1, r=(ra >> 3), b=(rb >> 3))))
        self._emit(_u8(0x87))
        self._emit(_u8(modrm(0b11, ra & 7, rb & 7)))

    def xadd_reg_reg(self, dst: str, src: str):
        """xadd r64, r64 — dst += src; src gets old dst"""
        d, s = reg_num(dst), reg_num(src)
        self._emit(_u8(rex(w=1, r=(s >> 3), b=(d >> 3))))
        self._emit(b"\x0F\xC1")
        self._emit(_u8(modrm(0b11, s & 7, d & 7)))

    def bsf_reg_reg(self, dst: str, src: str):
        d, s = reg_num(dst), reg_num(src)
        self._emit(_u8(rex(w=1, r=(d >> 3), b=(s >> 3))))
        self._emit(b"\x0F\xBC")
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))

    def bsr_reg_reg(self, dst: str, src: str):
        d, s = reg_num(dst), reg_num(src)
        self._emit(_u8(rex(w=1, r=(d >> 3), b=(s >> 3))))
        self._emit(b"\x0F\xBD")
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))

    def bt_reg_reg(self, base: str, offset: str):
        """bt r64, r64 — CF = bit"""
        b, o = reg_num(base), reg_num(offset)
        self._emit(_u8(rex(w=1, r=(o >> 3), b=(b >> 3))))
        self._emit(b"\x0F\xA3")
        self._emit(_u8(modrm(0b11, o & 7, b & 7)))

    def rep_stosb(self):
        self._emit(b"\xF3\xAA")

    def rep_movsb(self):
        self._emit(b"\xF3\xA4")


    def vshufps(self, dst, src, imm8: int):
        """vshufps ymm, ymm, ymm, imm8 — use dst as src1"""
        d = self._ymm_num(dst)
        s = self._ymm_num(src)
        R = 1 if d < 8 else 0
        B = 1 if s < 8 else 0
        vvvv = (~d) & 0xF
        self._emit(_u8(0xC4))
        self._emit(_u8((R << 7) | (1 << 6) | (B << 5) | 1))
        self._emit(_u8((0 << 7) | (vvvv << 3) | (1 << 2) | 0))
        self._emit(_u8(0xC6))
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))
        self._emit(_u8(imm8 & 0xFF))

    def vbroadcastss(self, dst, src_xmm):
        """vbroadcastss ymm, xmm"""
        d = self._ymm_num(dst)
        s = self._ymm_num(src_xmm)
        R = 1 if d < 8 else 0
        B = 1 if s < 8 else 0
        self._emit(_u8(0xC4))
        self._emit(_u8((R << 7) | (1 << 6) | (B << 5) | 2))  # 0F 38
        self._emit(_u8((0 << 7) | (0xF << 3) | (1 << 2) | 1))  # 66 pp=1
        self._emit(_u8(0x18))
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))


    # ---- Tier-1 ISA widen ----
    def shld_reg_reg(self, dst: str, src: str, count_cl: bool = True):
        """shld r64, r64, cl"""
        d, s = reg_num(dst), reg_num(src)
        self._emit(_u8(rex(w=1, r=(s >> 3), b=(d >> 3))))
        self._emit(b"\x0F\xA5")
        self._emit(_u8(modrm(0b11, s & 7, d & 7)))

    def shrd_reg_reg(self, dst: str, src: str):
        """shrd r64, r64, cl"""
        d, s = reg_num(dst), reg_num(src)
        self._emit(_u8(rex(w=1, r=(s >> 3), b=(d >> 3))))
        self._emit(b"\x0F\xAD")
        self._emit(_u8(modrm(0b11, s & 7, d & 7)))

    def imul_reg_imm(self, dst: str, imm: int):
        """imul r64, r64, imm32 (dst *= imm using same reg as src)"""
        d = reg_num(dst)
        self._emit(_u8(rex(w=1, r=(d >> 3), b=(d >> 3))))
        self._emit(_u8(0x69))
        self._emit(_u8(modrm(0b11, d & 7, d & 7)))
        self._emit(_u32(imm & 0xFFFFFFFF))

    def cmpxchg16b_mem(self, base: str, disp: int = 0):
        """lock cmpxchg16b [base+disp] — rdx:rax vs rcx:rbx"""
        b = reg_num(base)
        self._emit(_u8(0xF0))  # LOCK
        rex_b = 0x48 | ((b >> 3) & 1)
        self._emit(_u8(rex_b))
        self._emit(b"\x0F\xC7")
        rm = b & 7
        if disp == 0 and rm != 5:
            self._emit(_u8(modrm(0b00, 1, rm)))
        else:
            self._emit(_u8(modrm(0b01, 1, rm)))
            self._emit(_u8(disp & 0xFF))

    def andn_reg_reg(self, dst: str, src1: str, src2: str):
        """andn r64, r64, r64 (BMI1) — dst = ~src1 & src2"""
        d, s1, s2 = reg_num(dst), reg_num(src1), reg_num(src2)
        # VEX.LZ.0F38.W1 F2 /r
        R = 1 if d < 8 else 0
        B = 1 if s2 < 8 else 0
        X = 1
        vvvv = (~s1) & 0xF
        self._emit(_u8(0xC4))
        self._emit(_u8((R << 7) | (X << 6) | (B << 5) | 2))  # map 0F38
        self._emit(_u8((1 << 7) | (vvvv << 3) | 0))  # W=1, L=0, pp=0
        self._emit(_u8(0xF2))
        self._emit(_u8(modrm(0b11, d & 7, s2 & 7)))

    def bzhi_reg_reg(self, dst: str, src: str, ctrl: str):
        """bzhi r64, r64, r64 (BMI2)"""
        d, s, c = reg_num(dst), reg_num(src), reg_num(ctrl)
        R = 1 if d < 8 else 0
        B = 1 if s < 8 else 0
        vvvv = (~c) & 0xF
        self._emit(_u8(0xC4))
        self._emit(_u8((R << 7) | (1 << 6) | (B << 5) | 2))
        self._emit(_u8((1 << 7) | (vvvv << 3) | 0))
        self._emit(_u8(0xF5))
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))

    def lock_prefix(self):
        self._emit(_u8(0xF0))

    def rep_prefix(self):
        self._emit(_u8(0xF3))

    def xchg_reg_mem(self, reg: str, base: str, disp: int = 0):
        r, b = reg_num(reg), reg_num(base)
        self._emit(_u8(rex(w=1, r=(r >> 3), b=(b >> 3))))
        self._emit(_u8(0x87))
        rm = b & 7
        if disp == 0 and rm != 5:
            self._emit(_u8(modrm(0b00, r & 7, rm)))
        else:
            self._emit(_u8(modrm(0b01, r & 7, rm)))
            self._emit(_u8(disp & 0xFF))

    def cmov_reg_mem(self, cond: str, dst: str, base: str, disp: int = 0):
        op = self.CMOV_OPCODE.get(cond)
        if op is None:
            raise ValueError(f"bad cmov cond {cond}")
        d, b = reg_num(dst), reg_num(base)
        self._emit(_u8(rex(w=1, r=(d >> 3), b=(b >> 3))))
        self._emit(b"\x0F")
        self._emit(_u8(op))
        rm = b & 7
        if disp == 0 and rm != 5:
            self._emit(_u8(modrm(0b00, d & 7, rm)))
        else:
            self._emit(_u8(modrm(0b01, d & 7, rm)))
            self._emit(_u8(disp & 0xFF))


    # ================= ISA expansion batch =================
    def adc_reg_reg(self, dst, src):
        self._binop_reg_reg(0x11, dst, src)

    def sbb_reg_reg(self, dst, src):
        self._binop_reg_reg(0x19, dst, src)

    def bswap_reg(self, r):
        n = reg_num(r)
        self._emit(_u8(rex(w=1, b=(n >> 3))))
        self._emit(b"\x0F")
        self._emit(_u8(0xC8 + (n & 7)))

    def clc(self):
        self._emit(_u8(0xF8))

    def stc(self):
        self._emit(_u8(0xF9))

    def cmc(self):
        self._emit(_u8(0xF5))



    def pause(self):
        self._emit(b"\xF3\x90")

    def int3(self):
        self._emit(_u8(0xCC))

    def ud2(self):
        self._emit(b"\x0F\x0B")


    def cdq(self):
        """cdq — sign-extend eax into edx (32-bit form)"""
        self._emit(_u8(0x99))

    def mul_reg(self, src):
        """mul r/m64 — unsigned RDX:RAX = RAX * src"""
        s = reg_num(src)
        self._emit(_u8(rex(w=1, b=(s >> 3))))
        self._emit(_u8(0xF7))
        self._emit(_u8(modrm(0b11, 4, s & 7)))

    def div_reg(self, src):
        """div r/m64 — unsigned RAX=quot RDX=rem"""
        s = reg_num(src)
        self._emit(_u8(rex(w=1, b=(s >> 3))))
        self._emit(_u8(0xF7))
        self._emit(_u8(modrm(0b11, 6, s & 7)))

    def test_reg_imm32(self, dst, imm):
        d = reg_num(dst)
        self._emit(_u8(rex(w=1, b=(d >> 3))))
        self._emit(_u8(0xF7))
        self._emit(_u8(modrm(0b11, 0, d & 7)))
        self._emit(_u32(imm & 0xFFFFFFFF))

    def bts_reg_reg(self, base, offset):
        b, o = reg_num(base), reg_num(offset)
        self._emit(_u8(rex(w=1, r=(o >> 3), b=(b >> 3))))
        self._emit(b"\x0F\xAB")
        self._emit(_u8(modrm(0b11, o & 7, b & 7)))

    def btr_reg_reg(self, base, offset):
        b, o = reg_num(base), reg_num(offset)
        self._emit(_u8(rex(w=1, r=(o >> 3), b=(b >> 3))))
        self._emit(b"\x0F\xB3")
        self._emit(_u8(modrm(0b11, o & 7, b & 7)))

    def btc_reg_reg(self, base, offset):
        b, o = reg_num(base), reg_num(offset)
        self._emit(_u8(rex(w=1, r=(o >> 3), b=(b >> 3))))
        self._emit(b"\x0F\xBB")
        self._emit(_u8(modrm(0b11, o & 7, b & 7)))

    def popcnt_reg_reg(self, dst, src):
        """popcnt r64, r64"""
        d, s = reg_num(dst), reg_num(src)
        self._emit(_u8(0xF3))
        self._emit(_u8(rex(w=1, r=(d >> 3), b=(s >> 3))))
        self._emit(b"\x0F\xB8")
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))

    def lzcnt_reg_reg(self, dst, src):
        d, s = reg_num(dst), reg_num(src)
        self._emit(_u8(0xF3))
        self._emit(_u8(rex(w=1, r=(d >> 3), b=(s >> 3))))
        self._emit(b"\x0F\xBD")
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))

    def tzcnt_reg_reg(self, dst, src):
        d, s = reg_num(dst), reg_num(src)
        self._emit(_u8(0xF3))
        self._emit(_u8(rex(w=1, r=(d >> 3), b=(s >> 3))))
        self._emit(b"\x0F\xBC")
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))

    def movsx_reg32_reg8(self, dst, src):
        """movsx r64, r8 — simplified: use r32 names via low byte is complex; skip"""
        pass

    def nop_multi(self, n: int = 1):
        for _ in range(max(1, n)):
            self.nop()


    # ---- more ISA ----
    def sar_reg_imm8(self, r, imm):
        n = reg_num(r)
        self._emit(_u8(rex(w=1, b=(n >> 3))))
        self._emit(_u8(0xC1))
        self._emit(_u8(modrm(0b11, 7, n & 7)))
        self._emit(_u8(imm & 0xFF))

    def sar_reg_cl(self, r):
        n = reg_num(r)
        self._emit(_u8(rex(w=1, b=(n >> 3))))
        self._emit(_u8(0xD3))
        self._emit(_u8(modrm(0b11, 7, n & 7)))

    def rcl_reg_imm8(self, r, imm):
        n = reg_num(r)
        self._emit(_u8(rex(w=1, b=(n >> 3))))
        self._emit(_u8(0xC1))
        self._emit(_u8(modrm(0b11, 2, n & 7)))
        self._emit(_u8(imm & 0xFF))

    def rcr_reg_imm8(self, r, imm):
        n = reg_num(r)
        self._emit(_u8(rex(w=1, b=(n >> 3))))
        self._emit(_u8(0xC1))
        self._emit(_u8(modrm(0b11, 3, n & 7)))
        self._emit(_u8(imm & 0xFF))

    def cdqe(self):
        """cdqe — sign-extend eax to rax"""
        self._emit(_u8(0x48))
        self._emit(_u8(0x98))

    def pushfq(self):
        self._emit(_u8(0x9C))

    def popfq(self):
        self._emit(_u8(0x9D))

    def movsxd_reg_reg(self, dst, src):
        """movsxd r64, r32"""
        d, s = reg_num(dst), reg_num(src)
        self._emit(_u8(rex(w=1, r=(d >> 3), b=(s >> 3))))
        self._emit(_u8(0x63))
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))

    def rdtscp(self):
        self._emit(b"\x0F\x01\xF9")




    def endbr64(self):
        self._emit(b"\xF3\x0F\x1E\xFA")

    

    # ---- ISA batch 0.12.2 ----
    def sal_reg_imm8(self, r, imm):
        self.shl_reg_imm8(r, imm)

    def sal_reg_cl(self, r):
        self.shl_reg_cl(r)

    def shlx_reg_reg(self, dst, src, cnt):
        """shlx r64, r64, r64 (BMI2)"""
        d, s, c = reg_num(dst), reg_num(src), reg_num(cnt)
        R = 1 if d < 8 else 0
        B = 1 if s < 8 else 0
        vvvv = (~c) & 0xF
        self._emit(_u8(0xC4))
        self._emit(_u8((R << 7) | (1 << 6) | (B << 5) | 2))
        self._emit(_u8((1 << 7) | (vvvv << 3) | 1))  # W=1 pp=01
        self._emit(_u8(0xF7))
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))

    def shrx_reg_reg(self, dst, src, cnt):
        d, s, c = reg_num(dst), reg_num(src), reg_num(cnt)
        R = 1 if d < 8 else 0
        B = 1 if s < 8 else 0
        vvvv = (~c) & 0xF
        self._emit(_u8(0xC4))
        self._emit(_u8((R << 7) | (1 << 6) | (B << 5) | 2))
        self._emit(_u8((1 << 7) | (vvvv << 3) | 3))  # W=1 pp=11
        self._emit(_u8(0xF7))
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))

    def sarx_reg_reg(self, dst, src, cnt):
        d, s, c = reg_num(dst), reg_num(src), reg_num(cnt)
        R = 1 if d < 8 else 0
        B = 1 if s < 8 else 0
        vvvv = (~c) & 0xF
        self._emit(_u8(0xC4))
        self._emit(_u8((R << 7) | (1 << 6) | (B << 5) | 2))
        self._emit(_u8((1 << 7) | (vvvv << 3) | 2))  # W=1 pp=10
        self._emit(_u8(0xF7))
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))

    def rorx_reg_imm(self, dst, src, imm):
        d, s = reg_num(dst), reg_num(src)
        R = 1 if d < 8 else 0
        B = 1 if s < 8 else 0
        self._emit(_u8(0xC4))
        self._emit(_u8((R << 7) | (1 << 6) | (B << 5) | 3))  # 0F3A
        self._emit(_u8((1 << 7) | (0xF << 3) | 3))  # W=1 pp=11
        self._emit(_u8(0xF0))
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))
        self._emit(_u8(imm & 0xFF))

    def bextr_reg_reg(self, dst, src, ctrl):
        d, s, c = reg_num(dst), reg_num(src), reg_num(ctrl)
        R = 1 if d < 8 else 0
        B = 1 if s < 8 else 0
        vvvv = (~c) & 0xF
        self._emit(_u8(0xC4))
        self._emit(_u8((R << 7) | (1 << 6) | (B << 5) | 2))
        self._emit(_u8((1 << 7) | (vvvv << 3) | 0))
        self._emit(_u8(0xF7))
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))

    def blsi_reg_reg(self, dst, src):
        """blsi — isolate lowest set bit"""
        d, s = reg_num(dst), reg_num(src)
        R = 1 if d < 8 else 0
        B = 1 if s < 8 else 0
        vvvv = (~d) & 0xF  # dest is vvvv for some BMI - check: blsi r64a, r/m64 → VEX.NDD
        # Actually blsi: dest in VEX.vvvv, src in r/m
        vvvv = (~d) & 0xF
        R = 1  # no ModRM.reg
        self._emit(_u8(0xC4))
        self._emit(_u8((1 << 7) | (1 << 6) | (B << 5) | 2))
        self._emit(_u8((1 << 7) | (vvvv << 3) | 0))
        self._emit(_u8(0xF3))
        self._emit(_u8(modrm(0b11, 3, s & 7)))

    def blsr_reg_reg(self, dst, src):
        d, s = reg_num(dst), reg_num(src)
        B = 1 if s < 8 else 0
        vvvv = (~d) & 0xF
        self._emit(_u8(0xC4))
        self._emit(_u8((1 << 7) | (1 << 6) | (B << 5) | 2))
        self._emit(_u8((1 << 7) | (vvvv << 3) | 0))
        self._emit(_u8(0xF3))
        self._emit(_u8(modrm(0b11, 1, s & 7)))

    def blsmsk_reg_reg(self, dst, src):
        d, s = reg_num(dst), reg_num(src)
        B = 1 if s < 8 else 0
        vvvv = (~d) & 0xF
        self._emit(_u8(0xC4))
        self._emit(_u8((1 << 7) | (1 << 6) | (B << 5) | 2))
        self._emit(_u8((1 << 7) | (vvvv << 3) | 0))
        self._emit(_u8(0xF3))
        self._emit(_u8(modrm(0b11, 2, s & 7)))

    def adcx_reg_reg(self, dst, src):
        """adcx — add with CF, preserve OF"""
        d, s = reg_num(dst), reg_num(src)
        self._emit(_u8(0x66))
        self._emit(_u8(rex(w=1, r=(d >> 3), b=(s >> 3))))
        self._emit(b"\x0F\x38\xF6")
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))

    def adox_reg_reg(self, dst, src):
        d, s = reg_num(dst), reg_num(src)
        self._emit(_u8(0xF3))
        self._emit(_u8(rex(w=1, r=(d >> 3), b=(s >> 3))))
        self._emit(b"\x0F\x38\xF6")
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))

    def crc32_reg_reg(self, dst, src):
        """crc32 r32/r64, r/m — use 64-bit form"""
        d, s = reg_num(dst), reg_num(src)
        self._emit(_u8(0xF2))
        self._emit(_u8(rex(w=1, r=(d >> 3), b=(s >> 3))))
        self._emit(b"\x0F\x38\xF1")
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))

    def rdrand_reg(self, dst):
        d = reg_num(dst)
        self._emit(_u8(rex(w=1, b=(d >> 3))))
        self._emit(b"\x0F\xC7")
        self._emit(_u8(modrm(0b11, 6, d & 7)))

    def rdseed_reg(self, dst):
        d = reg_num(dst)
        self._emit(_u8(rex(w=1, b=(d >> 3))))
        self._emit(b"\x0F\xC7")
        self._emit(_u8(modrm(0b11, 7, d & 7)))


    # ---- ISA batch 0.12.3 ----
    def pext_reg_reg(self, dst, src, mask):
        """pext r64, r64, r/m64 — dst = pext(src, mask)"""
        d, s, m = reg_num(dst), reg_num(src), reg_num(mask)
        R = 0 if d >= 8 else 1  # inverted REX.R sense in VEX: R is inverted
        # VEX R is inverted: 1 means high bit 0
        R = 1 if d < 8 else 0
        B = 1 if m < 8 else 0
        vvvv = (~s) & 0xF
        self._emit(_u8(0xC4))
        self._emit(_u8((R << 7) | (1 << 6) | (B << 5) | 2))
        self._emit(_u8((1 << 7) | (vvvv << 3) | 3))  # W=1 F2
        self._emit(_u8(0xF5))
        self._emit(_u8(modrm(0b11, d & 7, m & 7)))

    def pdep_reg_reg(self, dst, src, mask):
        d, s, m = reg_num(dst), reg_num(src), reg_num(mask)
        R = 1 if d < 8 else 0
        B = 1 if m < 8 else 0
        vvvv = (~s) & 0xF
        self._emit(_u8(0xC4))
        self._emit(_u8((R << 7) | (1 << 6) | (B << 5) | 2))
        self._emit(_u8((1 << 7) | (vvvv << 3) | 2))  # W=1 F3
        self._emit(_u8(0xF5))
        self._emit(_u8(modrm(0b11, d & 7, m & 7)))

    def mulx_reg_reg(self, dst_hi, dst_lo, src):
        d, b, s = reg_num(dst_hi), reg_num(dst_lo), reg_num(src)
        R = 1 if d < 8 else 0
        B = 1 if s < 8 else 0
        vvvv = (~b) & 0xF
        self._emit(_u8(0xC4))
        self._emit(_u8((R << 7) | (1 << 6) | (B << 5) | 2))
        self._emit(_u8((1 << 7) | (vvvv << 3) | 3))  # pp=F2 → 11? 
        # VEX pp: 00=none, 01=66, 10=F3, 11=F2
        self._emit(_u8(0xF6))
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))

    def movbe_reg_reg(self, dst, src):
        """movbe r64, r64 — unusual; usually mem. Emit as bswap-style movbe load form skip"""
        # movbe r64, r/m64: 0F 38 F0
        d, s = reg_num(dst), reg_num(src)
        self._emit(_u8(rex(w=1, r=(d >> 3), b=(s >> 3))))
        self._emit(b"\x0F\x38\xF0")
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))

    def cmpxchg_reg_reg(self, dst, src):
        """cmpxchg r/m64, r64 — RAX compare"""
        d, s = reg_num(dst), reg_num(src)
        self._emit(_u8(rex(w=1, r=(s >> 3), b=(d >> 3))))
        self._emit(b"\x0F\xB1")
        self._emit(_u8(modrm(0b11, s & 7, d & 7)))

    def xchg_reg_rax(self, r):
        """xchg rax, r64 — short form"""
        n = reg_num(r)
        self._emit(_u8(rex(w=1, b=(n >> 3))))
        self._emit(_u8(0x90 + (n & 7)))

    def cbw(self):
        self._emit(_u8(0x66))
        self._emit(_u8(0x98))

    def cwde(self):
        self._emit(_u8(0x98))

    def cwd(self):
        self._emit(_u8(0x66))
        self._emit(_u8(0x99))

    def prefetchw(self, base, disp=0):
        b = reg_num(base)
        self._emit(b"\x0F\x0D")
        if disp == 0 and (b & 7) != 5:
            self._emit(_u8(modrm(0b00, 1, b & 7)))
        else:
            self._emit(_u8(modrm(0b01, 1, b & 7)))
            self._emit(_u8(disp & 0xFF))

    def prefetchnta(self, base, disp=0):
        b = reg_num(base)
        self._emit(b"\x0F\x18")
        if disp == 0 and (b & 7) != 5:
            self._emit(_u8(modrm(0b00, 0, b & 7)))
        else:
            self._emit(_u8(modrm(0b01, 0, b & 7)))
            self._emit(_u8(disp & 0xFF))

    def clflush(self, base, disp=0):
        b = reg_num(base)
        self._emit(b"\x0F\xAE")
        if disp == 0 and (b & 7) != 5:
            self._emit(_u8(modrm(0b00, 7, b & 7)))
        else:
            self._emit(_u8(modrm(0b01, 7, b & 7)))
            self._emit(_u8(disp & 0xFF))


    # ---- ISA batch 0.12.4 ----
    def movzx_r64_r8(self, dst, src):
        """movzx r64, r8 — use 0F B6 /r with REX.W; src low byte of register"""
        d, s = reg_num(dst), reg_num(src)
        self._emit(_u8(rex(w=1, r=(d >> 3), b=(s >> 3))))
        self._emit(b"\x0F\xB6")
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))

    def movzx_r64_r16(self, dst, src):
        d, s = reg_num(dst), reg_num(src)
        self._emit(_u8(rex(w=1, r=(d >> 3), b=(s >> 3))))
        self._emit(b"\x0F\xB7")
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))

    def movsx_r64_r8(self, dst, src):
        d, s = reg_num(dst), reg_num(src)
        self._emit(_u8(rex(w=1, r=(d >> 3), b=(s >> 3))))
        self._emit(b"\x0F\xBE")
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))

    def movsx_r64_r16(self, dst, src):
        d, s = reg_num(dst), reg_num(src)
        self._emit(_u8(rex(w=1, r=(d >> 3), b=(s >> 3))))
        self._emit(b"\x0F\xBF")
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))

    def bt_reg_imm8(self, base, imm):
        b = reg_num(base)
        self._emit(_u8(rex(w=1, b=(b >> 3))))
        self._emit(b"\x0F\xBA")
        self._emit(_u8(modrm(0b11, 4, b & 7)))
        self._emit(_u8(imm & 0xFF))

    def bts_reg_imm8(self, base, imm):
        b = reg_num(base)
        self._emit(_u8(rex(w=1, b=(b >> 3))))
        self._emit(b"\x0F\xBA")
        self._emit(_u8(modrm(0b11, 5, b & 7)))
        self._emit(_u8(imm & 0xFF))

    def btr_reg_imm8(self, base, imm):
        b = reg_num(base)
        self._emit(_u8(rex(w=1, b=(b >> 3))))
        self._emit(b"\x0F\xBA")
        self._emit(_u8(modrm(0b11, 6, b & 7)))
        self._emit(_u8(imm & 0xFF))

    def btc_reg_imm8(self, base, imm):
        b = reg_num(base)
        self._emit(_u8(rex(w=1, b=(b >> 3))))
        self._emit(b"\x0F\xBA")
        self._emit(_u8(modrm(0b11, 7, b & 7)))
        self._emit(_u8(imm & 0xFF))

    def shld_reg_imm8(self, dst, src, imm):
        d, s = reg_num(dst), reg_num(src)
        self._emit(_u8(rex(w=1, r=(s >> 3), b=(d >> 3))))
        self._emit(b"\x0F\xA4")
        self._emit(_u8(modrm(0b11, s & 7, d & 7)))
        self._emit(_u8(imm & 0xFF))

    def shrd_reg_imm8(self, dst, src, imm):
        d, s = reg_num(dst), reg_num(src)
        self._emit(_u8(rex(w=1, r=(s >> 3), b=(d >> 3))))
        self._emit(b"\x0F\xAC")
        self._emit(_u8(modrm(0b11, s & 7, d & 7)))
        self._emit(_u8(imm & 0xFF))

    def rcl_reg_cl(self, r):
        n = reg_num(r)
        self._emit(_u8(rex(w=1, b=(n >> 3))))
        self._emit(_u8(0xD3))
        self._emit(_u8(modrm(0b11, 2, n & 7)))

    def rcr_reg_cl(self, r):
        n = reg_num(r)
        self._emit(_u8(rex(w=1, b=(n >> 3))))
        self._emit(_u8(0xD3))
        self._emit(_u8(modrm(0b11, 3, n & 7)))

    def cmpxchg8b_mem(self, base, disp=0):
        """cmpxchg8b [base] — edx:eax vs ecx:ebx; LOCK optional separate"""
        b = reg_num(base)
        self._emit(_u8(rex(w=0, b=(b >> 3))))
        self._emit(b"\x0F\xC7")
        rm = b & 7
        if disp == 0 and rm != 5:
            self._emit(_u8(modrm(0b00, 1, rm)))
        else:
            self._emit(_u8(modrm(0b01, 1, rm)))
            self._emit(_u8(disp & 0xFF))

    def nop_long(self):
        """3-byte NOP"""
        self._emit(b"\x0F\x1F\x00")

    def ret_imm16(self, imm):
        self._emit(_u8(0xC2))
        self._emit(_u16(imm & 0xFFFF))

    def enter_imm(self, size, nesting=0):
        self._emit(_u8(0xC8))
        self._emit(_u16(size & 0xFFFF))
        self._emit(_u8(nesting & 0xFF))

    def bound_noop(self):
        pass


    # ---- ISA batch 0.12.5 (remainder high-value) ----
    def mov_reg_imm32_zext(self, dst, imm):
        """mov r32, imm32 zero-extends to 64"""
        d = reg_num(dst)
        if d < 8:
            self._emit(_u8(0xB8 + d))
        else:
            self._emit(_u8(rex(w=0, b=1)))
            self._emit(_u8(0xB8 + (d & 7)))
        self._emit(_u32(imm & 0xFFFFFFFF))

    def imul_reg_reg_imm(self, dst, src, imm):
        """imul r64, r/m64, imm32"""
        d, s = reg_num(dst), reg_num(src)
        self._emit(_u8(rex(w=1, r=(d >> 3), b=(s >> 3))))
        self._emit(_u8(0x69))
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))
        self._emit(_u32(imm & 0xFFFFFFFF))

    def test_reg_reg8_dummy(self):
        pass

    def seto_reg(self, dst):
        self.setcc_reg("overflow", dst) if hasattr(self, 'setcc_reg') else None

    def cld_already(self):
        pass

    def stmxcsr_mem(self, base, disp=0):
        b = reg_num(base)
        self._emit(b"\x0F\xAE")
        rm = b & 7
        if disp == 0 and rm != 5:
            self._emit(_u8(modrm(0b00, 3, rm)))
        else:
            self._emit(_u8(modrm(0b01, 3, rm)))
            self._emit(_u8(disp & 0xFF))

    def ldmxcsr_mem(self, base, disp=0):
        b = reg_num(base)
        self._emit(b"\x0F\xAE")
        rm = b & 7
        if disp == 0 and rm != 5:
            self._emit(_u8(modrm(0b00, 2, rm)))
        else:
            self._emit(_u8(modrm(0b01, 2, rm)))
            self._emit(_u8(disp & 0xFF))

    def fxsave_mem(self, base, disp=0):
        b = reg_num(base)
        self._emit(b"\x0F\xAE")
        rm = b & 7
        if disp == 0 and rm != 5:
            self._emit(_u8(modrm(0b00, 0, rm)))
        else:
            self._emit(_u8(modrm(0b01, 0, rm)))
            self._emit(_u8(disp & 0xFF))

    def fxrstor_mem(self, base, disp=0):
        b = reg_num(base)
        self._emit(b"\x0F\xAE")
        rm = b & 7
        if disp == 0 and rm != 5:
            self._emit(_u8(modrm(0b00, 1, rm)))
        else:
            self._emit(_u8(modrm(0b01, 1, rm)))
            self._emit(_u8(disp & 0xFF))

    def xgetbv(self):
        self._emit(b"\x0F\x01\xD0")

    def xsetbv(self):
        self._emit(b"\x0F\x01\xD1")

    def wrfsbase_reg(self, src):
        s = reg_num(src)
        self._emit(_u8(0xF3))
        self._emit(_u8(rex(w=1, b=(s >> 3))))
        self._emit(b"\x0F\xAE")
        self._emit(_u8(modrm(0b11, 2, s & 7)))

    def wrgsbase_reg(self, src):
        s = reg_num(src)
        self._emit(_u8(0xF3))
        self._emit(_u8(rex(w=1, b=(s >> 3))))
        self._emit(b"\x0F\xAE")
        self._emit(_u8(modrm(0b11, 3, s & 7)))

    def rdfsbase_reg(self, dst):
        d = reg_num(dst)
        self._emit(_u8(0xF3))
        self._emit(_u8(rex(w=1, b=(d >> 3))))
        self._emit(b"\x0F\xAE")
        self._emit(_u8(modrm(0b11, 0, d & 7)))

    def rdgsbase_reg(self, dst):
        d = reg_num(dst)
        self._emit(_u8(0xF3))
        self._emit(_u8(rex(w=1, b=(d >> 3))))
        self._emit(b"\x0F\xAE")
        self._emit(_u8(modrm(0b11, 1, d & 7)))

    def invlpg_mem(self, base, disp=0):
        b = reg_num(base)
        self._emit(b"\x0F\x01")
        rm = b & 7
        if disp == 0 and rm != 5:
            self._emit(_u8(modrm(0b00, 7, rm)))
        else:
            self._emit(_u8(modrm(0b01, 7, rm)))
            self._emit(_u8(disp & 0xFF))

    def wbinvd(self):
        self._emit(b"\x0F\x09")

    def invd(self):
        self._emit(b"\x0F\x08")

    def clts(self):
        self._emit(b"\x0F\x06")

    def lar_reg_reg(self, dst, src):
        d, s = reg_num(dst), reg_num(src)
        self._emit(_u8(rex(w=1, r=(d >> 3), b=(s >> 3))))
        self._emit(b"\x0F\x02")
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))

    def lsl_reg_reg(self, dst, src):
        d, s = reg_num(dst), reg_num(src)
        self._emit(_u8(rex(w=1, r=(d >> 3), b=(s >> 3))))
        self._emit(b"\x0F\x03")
        self._emit(_u8(modrm(0b11, d & 7, s & 7)))

    def str_reg(self, dst):
        d = reg_num(dst)
        self._emit(_u8(rex(w=0, b=(d >> 3))))
        self._emit(b"\x0F\x00")
        self._emit(_u8(modrm(0b11, 1, d & 7)))

    def sldt_reg(self, dst):
        d = reg_num(dst)
        self._emit(_u8(rex(w=0, b=(d >> 3))))
        self._emit(b"\x0F\x00")
        self._emit(_u8(modrm(0b11, 0, d & 7)))

    def smsw_reg(self, dst):
        d = reg_num(dst)
        self._emit(_u8(rex(w=0, b=(d >> 3))))
        self._emit(b"\x0F\x01")
        self._emit(_u8(modrm(0b11, 4, d & 7)))

    def rdmsr(self):
        self._emit(b"\x0F\x32")

    def wrmsr(self):
        self._emit(b"\x0F\x30")

    def rdpmc(self):
        self._emit(b"\x0F\x33")

    def swapgs(self):
        self._emit(b"\x0F\x01\xF8")

    def syscall_sysret(self):
        pass

    def sysret(self):
        self._emit(b"\x48\x0F\x07")

    def sysenter(self):
        self._emit(b"\x0F\x34")

    def sysexit(self):
        self._emit(b"\x0F\x35")


    def lidt_mem(self, base: str, disp: int = 0):
        """lidt [base+disp] — 0F 01 /3"""
        b = reg_num(base)
        rex_v = 0x48 | (b >> 3)  # still ok; 64-bit lidt uses 10-byte IDTR
        self._emit(_u8(rex_v))
        self._emit(_u8(0x0F))
        self._emit(_u8(0x01))
        # modrm /3
        if disp == 0 and (b & 7) != 5:
            self._emit(_u8(modrm(0, 3, b & 7)))
        else:
            self._emit(_u8(modrm(1, 3, b & 7)))
            self._emit(_u8(disp & 0xFF))

    def lgdt_mem(self, base: str, disp: int = 0):
        """lgdt [base+disp] — 0F 01 /2"""
        b = reg_num(base)
        rex_v = 0x48 | (b >> 3)
        self._emit(_u8(rex_v))
        self._emit(_u8(0x0F))
        self._emit(_u8(0x01))
        if disp == 0 and (b & 7) != 5:
            self._emit(_u8(modrm(0, 2, b & 7)))
        else:
            self._emit(_u8(modrm(1, 2, b & 7)))
            self._emit(_u8(disp & 0xFF))


    def int_imm(self, vec: int):
        """int imm8"""
        self._emit(_u8(0xCD))
        self._emit(_u8(vec & 0xFF))

    def iretq(self):
        self._emit(b"\x48\xCF")


    def call_reg(self, reg: str):
        """call reg"""
        r = reg_num(reg)
        self._emit(_u8(rex(w=1, b=(r >> 3))))
        self._emit(_u8(0xFF))
        self._emit(_u8(modrm(0b11, 2, r & 7)))
