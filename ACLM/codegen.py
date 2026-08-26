"""ACLM codegen — AST → x86-64 ELF64 (no nasm/ld)."""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from . import ast_nodes as A
from .regs import resolve, SCRATCH, SYSCALL_ARGS
from .x64enc import Assembler
from .elfwriter import (build_elf64_exe, build_elf64_exe_debug, build_elf32_multiboot,
                        build_multiboot_header, build_elf64_exe_wx, wx_code_data_file_offsets, build_elf64_with_symtab)

NAMED_SYSCALLS = {
    "read": 0, "write": 1, "open": 2, "close": 3,
    "lseek": 8, "seek": 8, "mmap": 9, "mprotect": 10, "munmap": 11,
    "exit": 60, "exit_group": 231, "getpid": 39, "fork": 57,
    "wait4": 61, "nanosleep": 35, "clock_gettime": 228,
    "socket": 41, "connect": 42, "sendto": 44, "recvfrom": 45,
    "bind": 49, "listen": 50, "ioctl": 16, "brk": 12,
}


class CodegenError(Exception):
    pass


class CodeGenerator:
    def __init__(self, filename: str = "<src>"):
        self.filename = filename
        self.asm = Assembler()
        self.data_layout: Dict[str, int] = {}
        self.data_bytes = bytearray()
        self.data_consts: Dict[str, int] = {}
        self.string_lens: Dict[str, int] = {}
        self.label_i = 0
        self.needs_pulse = False
        self.emit_listing = False
        self.teach_mode = False
        self.deterministic = False
        self._assert_bytes = []  # (name, limit, op, code_off)
        self._assert_sizes = []
        self._frame_diagrams = []  # list of text blocks
        self._section_hints = []
        self._listing_lines = []
        self._teach_map = []  # (src_line, src_hint, code_start)
        self.baremetal = False
        self.debug_dwarf = False
        self.use_wx = False
        self.needs_thr_futex = False
        self.line_entries = []
        self.structs: Dict[str, dict] = {}  # name -> {fields: {fname: offset}, size: int}
        self.fn_locals: Dict[str, int] = {}  # local name -> rbp-relative offset (negative)
        self.fn_args: Dict[str, str] = {}  # arg name -> physical reg
        self.in_fn = False

    def new_label(self, prefix: str = "L") -> str:
        self.label_i += 1
        return f"__aclm_{prefix}_{self.label_i}"

    def generate(self, program: A.Program) -> bytes:
        # Detect freestanding/kernel target early (before emit / default exit)
        for s in program.statements:
            if isinstance(s, A.TargetBaremetal):
                self.baremetal = True
                break
        self._collect_structs(program.statements)
        self._collect_data(program.statements)
        for s in program.statements:
            if isinstance(s, A.MetalDeterministic):
                self.deterministic = True
                self.asm.deterministic = True
                break
        if self._uses_pulse(program.statements):
            self.data_layout["__timespec"] = len(self.data_bytes)
            self.data_bytes += b"\x00" * 16
        if self._uses_thread(program.statements):
            self.data_layout["__thr_futex"] = len(self.data_bytes)
            self.data_bytes += b"\x00" * 24  # [done][joined][spawn_count]
            self.needs_thr_futex = True
        # Emit top-level first (skip fn defs), then functions (so entry is main)
        fns = []
        for s in program.statements:
            if isinstance(s, A.FnDef):
                fns.append(s)
            else:
                self._emit(s)
        if not self.baremetal and not self._ends_exit(program.statements):
            self.asm.mov_reg_imm64("rax", 60)
            self.asm.xor_reg_reg("rdi", "rdi")
            self.asm.syscall()
        elif self.baremetal and not self._ends_halt(program.statements):
            # Freestanding: never emit Linux exit; safety hlt is in ELF wrapper epilogue
            pass

        for s in fns:
            self._emit(s)

        # link code labels + data labels (RIP-relative)
        from .elfwriter import EHDR_SIZE, PHDR_SIZE
        code_len = len(self.asm.code)
        offs = dict(self.asm.labels)
        for name, off in self.data_layout.items():
            offs[f"__data_{name}"] = code_len + off
        if self.use_wx:
            # padding between code and data in W^X layout
            code_len = len(self.asm.code)
            code_off, data_off = wx_code_data_file_offsets(code_len)
            pad = (data_off - code_off) - code_len
            for name, off in list(offs.items()):
                if name.startswith("__data_"):
                    offs[name] = off + pad
        self.asm.link(base_offset_map=offs)
        code_b = bytes(self.asm.code)
        data_b = bytes(self.data_bytes)
        self._run_asserts(code_b, data_b)
        if self.emit_listing or self.teach_mode:
            self._build_listing(code_b)
        if self.baremetal:
            return self._build_baremetal_kernel(code_b, data_b)
        if self.debug_dwarf:
            syms = [(n, o) for n, o in sorted(self.asm.labels.items())]
            return build_elf64_with_symtab(
                code_b, data_b, symbols=syms, entry_offset_in_code=0,
            )
        if self.use_wx:
            return build_elf64_exe_wx(code_b, data_b)
        return build_elf64_exe(code_b, data_b)

    def _collect_structs(self, stmts: List[A.Node]):
        for s in stmts:
            if isinstance(s, A.StructDef):
                fields = {}
                off = 0
                for fname, fsize in s.fields:
                    fields[fname] = off
                    off += fsize
                self.structs[s.name] = {"fields": fields, "size": off}
            elif isinstance(s, A.FnDef):
                self._collect_structs(s.body)

    def _uses_thread(self, stmts: List[A.Node]) -> bool:
        for s in stmts:
            if isinstance(s, (A.ThreadSpawn, A.ThreadJoin, A.ThreadJoinAll, A.ThreadExit)):
                return True
        return False

    def _uses_pulse(self, stmts: List[A.Node]) -> bool:
        for s in stmts:
            if isinstance(s, (A.PulseSleep, A.PulseNow)):
                return True
        return False

    def _ends_halt(self, stmts: List[A.Node]) -> bool:
        """True if last meaningful stmt is chip:halt / hlt (baremetal)."""
        for s in reversed(stmts):
            if isinstance(s, (A.TargetBaremetal, A.DataAlloc, A.DataConst, A.DataBytes, A.DataAlign)):
                continue
            if isinstance(s, A.ChipHalt):
                return True
            return False
        return False

    def _ends_exit(self, stmts: List[A.Node]) -> bool:
        if not stmts:
            return False
        s = stmts[-1]
        if isinstance(s, A.SysCall):
            if isinstance(s.num, str) and s.num.lower() in ("exit", "60"):
                return True
            if isinstance(s.num, A.Number) and s.num.value == 60:
                return True
        return False

    def _collect_data(self, stmts: List[A.Node]):
        off = 0
        for s in stmts:
            if isinstance(s, A.DataAlloc):
                sz = s.size
                if isinstance(sz, str):
                    if sz not in self.structs:
                        raise CodegenError(f"data:alloc unknown struct/size '{sz}'")
                    sz = self.structs[sz]["size"]
                self.data_layout[s.name] = off
                self.data_bytes += b"\x00" * sz
                off += sz
            elif isinstance(s, A.DataAlign):
                a = s.align
                pad = (a - (off % a)) % a
                self.data_bytes += b"\x00" * pad
                off += pad
            elif isinstance(s, A.DataBytes):
                self.data_layout[s.name] = off
                self.string_lens[s.name] = len(s.values)  # length for wire:len if needed
                self.data_bytes += bytes(s.values)
                off += len(s.values)
            elif isinstance(s, A.DataConst):
                if isinstance(s.value, A.Number):
                    self.data_consts[s.name] = s.value.value
                    # also place 8-byte in data for address-taking if needed
                    self.data_layout[s.name] = off
                    v = s.value.value & ((1 << 64) - 1)
                    self.data_bytes += v.to_bytes(8, "little")
                    off += 8
                elif isinstance(s.value, A.String):
                    raw = s.value.value.encode("utf-8") + b"\x00"
                    self.data_layout[s.name] = off
                    self.string_lens[s.name] = len(raw) - 1
                    self.data_bytes += raw
                    off += len(raw)

    def _eval(self, node: Any, dst_phys: str):
        if isinstance(node, A.Number):
            self.asm.mov_reg_imm64(dst_phys, node.value)
        elif isinstance(node, A.Reg):
            src = resolve(node.name)
            if src != dst_phys:
                self.asm.mov_reg_reg(dst_phys, src)
        elif isinstance(node, A.Ident):
            if node.name in self.fn_args:
                src = self.fn_args[node.name]
                if src != dst_phys:
                    self.asm.mov_reg_reg(dst_phys, src)
            elif node.name in self.fn_locals:
                # local variable: load from [rbp + off]
                off = self.fn_locals[node.name]
                self.asm.mov_reg_mem(dst_phys, "rbp", off)
            elif node.name in self.data_consts and node.name not in self.string_lens:
                self.asm.mov_reg_imm64(dst_phys, self.data_consts[node.name])
            elif node.name in self.data_layout:
                self.asm.lea_reg_label(dst_phys, f"__data_{node.name}")
            elif node.name in self.structs:
                # bare struct name → size
                self.asm.mov_reg_imm64(dst_phys, self.structs[node.name]["size"])
            else:
                raise CodegenError(
                    f"unknown identifier '{node.name}'\n"
                    f"  hint: data names={list(self.data_layout.keys())[:12]} "
                    f"structs={list(self.structs.keys())[:8]} "
                    f"locals={list(self.fn_locals.keys())}"
                )
        elif isinstance(node, A.StructFieldRef):
            if node.struct not in self.structs:
                raise CodegenError(
                    f"unknown struct '{node.struct}'\n"
                    f"  known structs: {list(self.structs.keys())}"
                )
            fields = self.structs[node.struct]["fields"]
            if node.field not in fields:
                raise CodegenError(
                    f"unknown field '{node.struct}.{node.field}'\n"
                    f"  {node.struct} fields: "
                    + ", ".join(f"{fn}@+{off}" for fn, off in self.structs[node.struct]["fields"].items())
                    + f" (size {self.structs[node.struct]['size']})"
                )
            self.asm.mov_reg_imm64(dst_phys, fields[node.field])
        elif isinstance(node, A.BinExpr):
            # Evaluate left → r11, right → r12, combine into dst
            # Avoid SCRATCH(=rbp) so function frames stay intact
            self._eval(node.left, "r11")
            self.asm.push_reg("r11")
            self._eval(node.right, "r12")
            self.asm.pop_reg("r11")
            if node.op == "+":
                self.asm.add_reg_reg("r11", "r12")
            elif node.op == "-":
                self.asm.sub_reg_reg("r11", "r12")
            elif node.op == "*":
                self.asm.imul_reg_reg("r11", "r12")
            else:
                raise CodegenError(f"unsupported bin op {node.op}")
            if dst_phys != "r11":
                self.asm.mov_reg_reg(dst_phys, "r11")
        else:
            raise CodegenError(f"bad operand {type(node).__name__}")

    def _emit(self, s: A.Node):
        if getattr(s, 'line', 0):
            self.line_entries.append((len(self.asm.code), int(s.line)))
        if self.emit_listing or self.teach_mode:
            hint = type(s).__name__
            self._teach_map.append((int(getattr(s, 'line', 0) or 0), hint, len(self.asm.code)))
        if isinstance(s, A.Label):
            self.asm.label(f"__lbl_{s.name}")
        elif isinstance(s, A.Goto):
            self.asm.jmp(f"__lbl_{s.label}")
        elif isinstance(s, A.JumpIf):
            self.asm.jcc(s.cond, f"__lbl_{s.label}")
        elif isinstance(s, A.Cmp):
            # Only r15 is non-user GP. Save r11, use r11+r15 as temps, restore.
            self.asm.push_reg("r11")
            self._eval(s.left, SCRATCH)
            self.asm.mov_reg_reg("r11", SCRATCH)
            self.asm.push_reg("r11")
            self._eval(s.right, SCRATCH)
            self.asm.pop_reg("r11")
            self.asm.cmp_reg_reg("r11", SCRATCH)
            self.asm.pop_reg("r11")
        elif isinstance(s, A.CpuBin):
            self._cpu_bin(s)
        elif isinstance(s, A.CpuUnary):
            self._cpu_unary(s)
        elif isinstance(s, (A.DataAlloc, A.DataConst, A.DataBytes, A.DataAlign, A.MetalRegs, A.MetalDeterministic, A.SectionAt)):
            pass
        elif isinstance(s, A.MemLoad):
            self._mem_load(s)
        elif isinstance(s, A.MemStore):
            self._mem_store(s)
        elif isinstance(s, A.SysCall):
            self._syscall(s)
        elif isinstance(s, A.Call):
            # SysV user call: rdi,rsi,rdx,rcx,r8,r9
            # Eval into r11 (not SCRATCH/rbp) so nested calls inside frames work
            arg_regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
            for arg in s.args[:6]:
                self._eval(arg, "r11")
                self.asm.push_reg("r11")
            for i in range(len(s.args[:6]) - 1, -1, -1):
                self.asm.pop_reg(arg_regs[i])
            self.asm.call(f"__lbl_{s.label}")
        elif isinstance(s, A.Ret):
            if self.in_fn:
                self._fn_epilogue()
            else:
                self.asm.ret()
        elif isinstance(s, A.StackPush):
            self._eval(s.value, "r11")
            self.asm.push_reg("r11")
        elif isinstance(s, A.StackPop):
            self.asm.pop_reg(resolve(s.dest))
        elif isinstance(s, A.BlastFill):
            self._blast_fill(s)
        elif isinstance(s, A.BlastCopy):
            self._blast_copy(s)
        elif isinstance(s, A.WireLen):
            self._wire_len(s)
        elif isinstance(s, A.WireCmp):
            self._wire_cmp(s)
        elif isinstance(s, A.WireCopy):
            self._wire_copy(s)
        elif isinstance(s, A.WireEmit):
            self._wire_emit(s)
        elif isinstance(s, A.TrapNeg):
            self.asm.test_reg_reg("rax", "rax")
            self.asm.jcc("lt", f"__lbl_{s.label}")
        elif isinstance(s, A.CellMap):
            self._cell_map(s)
        elif isinstance(s, A.CellMapFile):
            self._cell_mapfile(s)
        elif isinstance(s, A.CellProtect):
            self._cell_protect(s)
        elif isinstance(s, A.SigAction):
            self._sig_action(s)
        elif isinstance(s, A.SigReturn):
            self.asm.mov_reg_imm64("rax", 15)  # rt_sigreturn
            self.asm.syscall()
        elif isinstance(s, A.CellFree):
            self._cell_free(s)
        elif isinstance(s, A.GateCas):
            self._gate_cas(s)
        elif isinstance(s, A.GateSpin):
            self._gate_spin(s)
        elif isinstance(s, A.PulseSleep):
            self._pulse_sleep(s)
        elif isinstance(s, A.PulseNow):
            self._pulse_now(s)
        elif isinstance(s, A.FlagSetcc):
            self.asm.setcc_reg(s.cond, resolve(s.dest))
        elif isinstance(s, A.FlagsClear):
            self.asm.cld()
        elif isinstance(s, A.FlagsSetDF):
            self.asm.std()
        elif isinstance(s, A.CpuMovExt):
            self._cpu_movext(s)
        elif isinstance(s, A.ChipTicks):
            self.asm.rdtsc()
            # low 32 in eax → zero-extend already in rax on x64 after rdtsc? edx:eax
            # put full low in dest from eax
            dst = resolve(s.dest)
            if dst != "rax":
                self.asm.mov_reg_reg(dst, "rax")
            # optionally clear upper: and with 0xffffffff
            self.asm.mov_reg_imm64(SCRATCH, 0xFFFFFFFF)
            self.asm.and_reg_reg(dst, SCRATCH)
        elif isinstance(s, A.ChipId):
            self._eval(s.leaf, "rax")
            self.asm.xor_reg_reg("rcx", "rcx")
            self.asm.cpuid()
            mapping = [
                (s.dest_a, "rax"),
                (s.dest_b, "rbx"),
                (s.dest_c, "rcx"),
                (s.dest_d, "rdx"),
            ]
            # save results to stack then pop to dests to avoid clobber
            for _, src in reversed(mapping):
                self.asm.push_reg(src)
            for dest, _ in mapping:
                self.asm.pop_reg(resolve(dest))
        elif isinstance(s, A.ChipCli):
            self.asm.cli()
        elif isinstance(s, A.ChipSti):
            self.asm.sti()
        elif isinstance(s, A.ChipHalt):
            self.asm.hlt()
        elif isinstance(s, A.ChipSerialInit):
            self._serial_init()
        elif isinstance(s, A.ChipSerialPutc):
            self._serial_putc(s)
        elif isinstance(s, A.ChipLidt):
            self.asm.lidt_mem(resolve(s.base), 0)
        elif isinstance(s, A.ChipLgdt):
            self.asm.lgdt_mem(resolve(s.base), 0)
        elif isinstance(s, A.ChipKbdPoll):
            self._kbd_poll(s)
        elif isinstance(s, A.ChipInt):
            self.asm.int_imm(s.vec)
        elif isinstance(s, A.KernelHeapInit):
            self._kernel_heap_init(s)
        elif isinstance(s, A.KernelHeapAlloc):
            self._kernel_heap_alloc(s)
        elif isinstance(s, A.KernelCtxSave):
            self._kernel_ctx_save(s)
        elif isinstance(s, A.KernelCtxLoad):
            self._kernel_ctx_load(s)
        elif isinstance(s, A.KernelIdtInstall):
            self._kernel_idt_install(s)
        elif isinstance(s, A.ChipPitInit):
            self._pit_init(s)
        elif isinstance(s, A.ChipPicRemap):
            self._pic_remap(s)
        elif isinstance(s, A.KernelCoopSwitch):
            self._kernel_coop_switch(s)
        elif isinstance(s, A.KernelPrintkStr):
            self._kernel_printk_str(s)
        elif isinstance(s, A.KernelPanic):
            self._kernel_panic(s)
        elif isinstance(s, A.KernelTickInstall):
            self._kernel_tick_install(s)
        elif isinstance(s, A.KernelTickRead):
            self._kernel_tick_read(s)
        elif isinstance(s, A.KernelRamfsInit):
            self._kernel_ramfs_init(s)
        elif isinstance(s, A.KernelRamfsPut):
            self._kernel_ramfs_put(s)
        elif isinstance(s, A.KernelRamfsGet):
            self._kernel_ramfs_get(s)
        elif isinstance(s, A.KernelNetInit):
            self._kernel_net_init(s)
        elif isinstance(s, A.KernelNetPoll):
            self._kernel_net_poll(s)
        elif isinstance(s, A.KernelCsRing):
            self._kernel_cs_ring(s)
        elif isinstance(s, A.KernelEnterUser):
            self._kernel_enter_user(s)
        elif isinstance(s, A.KernelPfInstall):
            self._kernel_pf_install(s)
        elif isinstance(s, A.KernelNetAllowPort):
            self._kernel_net_allow(s)
        elif isinstance(s, A.KernelNetCheckPort):
            self._kernel_net_check(s)
        elif isinstance(s, A.KernelPreemptArm):
            self._kernel_preempt_arm(s)
        elif isinstance(s, A.KernelSyscallInit):
            self._kernel_syscall_init(s)
        elif isinstance(s, A.KernelSysret):
            self.asm.sysret()
        elif isinstance(s, A.KernelNicBar):
            self._kernel_nic_bar(s)
        elif isinstance(s, A.KernelNicRegRead):
            self._kernel_nic_read(s)
        elif isinstance(s, A.KernelNicRegWrite):
            self._kernel_nic_write(s)
        elif isinstance(s, A.KernelIrqFullSave):
            self._kernel_irq_full_save_on(s)
        elif isinstance(s, A.KernelSyscallTableInit):
            self._kernel_syscall_table_init(s)
        elif isinstance(s, A.KernelSyscallRegister):
            self._kernel_syscall_register(s)
        elif isinstance(s, A.KernelNmiInstall):
            self._kernel_nmi_install(s)
        elif isinstance(s, A.KernelDmaRingInit):
            self._kernel_dma_ring_init(s)
        elif isinstance(s, A.KernelDmaRingPush):
            self._kernel_dma_ring_push(s)
        elif isinstance(s, A.KernelDmaRingPop):
            self._kernel_dma_ring_pop(s)
        elif isinstance(s, A.GateFence):
            k = (s.kind or "mfence").lower()
            if k == "lfence":
                self.asm.lfence()
            elif k == "sfence":
                self.asm.sfence()
            else:
                self.asm.mfence()
        elif isinstance(s, A.PortOut):
            self._eval(s.port, "rdx")
            self._eval(s.value, "rax")
            self.asm.out_dx_al()
        elif isinstance(s, A.PortIn):
            self._eval(s.port, "rdx")
            self.asm.in_al_dx()
            dst = resolve(s.dest)
            if dst != "rax":
                self.asm.mov_reg_reg(dst, "rax")
            # use SCRATCH (r15), never r11 (=reg10)
            self.asm.mov_reg_imm64(SCRATCH, 0xFF)
            self.asm.and_reg_reg(dst, SCRATCH)
        elif isinstance(s, A.VecLoad):
            self._vec_load(s)
        elif isinstance(s, A.VecStore):
            self._vec_store(s)
        elif isinstance(s, A.VecBin):
            getattr(self.asm, s.op)(s.dst, s.src)
        elif isinstance(s, A.CpuLea):
            self._cpu_lea(s)
        elif isinstance(s, A.CpuTest):
            self._cpu_test(s)
        elif isinstance(s, A.CpuCmov):
            # eval src into r15 (scratch), never clobber user regs
            self._eval(s.src, SCRATCH)
            self.asm.cmov_reg_reg(s.cond, resolve(s.dest), SCRATCH)
        elif isinstance(s, A.RawBytes):
            self.asm.raw_bytes(bytes(s.hex_parts))
        elif isinstance(s, A.MetalDeterministic):
            self.deterministic = True
            if hasattr(self.asm, "deterministic"):
                self.asm.deterministic = True
        elif isinstance(s, A.SectionAt):
            self._section_hints.append(f"section:{s.name} at:0x{s.addr:x}")
        elif isinstance(s, A.CpuLeaRip):
            self.asm.lea_reg_label(resolve(s.dest), f"__data_{s.label}")
        elif isinstance(s, A.CpuLeaAbs):
            self.asm.mov_reg_imm64(resolve(s.dest), s.addr)
        elif isinstance(s, A.AssertBytes):
            self._assert_bytes.append((s.name, s.limit, s.op, len(self.asm.code)))
        elif isinstance(s, A.AssertSize):
            self._assert_sizes.append((s.what, s.limit))
        elif isinstance(s, A.Include):
            pass  # resolved before parse
        elif isinstance(s, A.ThreadSpawn):
            self._thread_spawn(s)
        elif isinstance(s, A.ThreadJoin):
            self._thread_join(s)
        elif isinstance(s, A.ThreadJoinAll):
            self._thread_join_all(s)
        elif isinstance(s, A.ThreadExit):
            self._thread_exit(s)
        elif isinstance(s, A.VecVBin):
            if s.op == "vshufps":
                self.asm.vshufps(s.dst, s.src, s.imm)
            elif s.op == "vbroadcastss":
                self.asm.vbroadcastss(s.dst, s.src)
            else:
                getattr(self.asm, s.op)(s.dst, s.src)
        elif isinstance(s, A.VecVLoad):
            base = self._base_phys(s.base) if hasattr(self, '_base_phys') else self._base_reg(s.base)
            self.asm.vmovups_load(s.ymm, base, s.offset)
        elif isinstance(s, A.VecVStore):
            base = self._base_phys(s.base) if hasattr(self, '_base_phys') else self._base_reg(s.base)
            self.asm.vmovups_store(base, s.ymm, s.offset)
        elif isinstance(s, A.ErrStatus):
            dst = resolve(s.dest)
            if dst != "rax":
                self.asm.mov_reg_reg(dst, "rax")
        elif isinstance(s, A.CpuXchg):
            self.asm.xchg_reg_reg(resolve(s.a), resolve(s.b))
        elif isinstance(s, A.CpuXadd):
            self.asm.xadd_reg_reg(resolve(s.dest), resolve(s.src))
        elif isinstance(s, A.CpuBitScan):
            self._eval(s.src, SCRATCH)
            if s.op == "bsf":
                self.asm.bsf_reg_reg(resolve(s.dest), SCRATCH)
            else:
                self.asm.bsr_reg_reg(resolve(s.dest), SCRATCH)
        elif isinstance(s, A.CpuBt):
            self._eval(s.offset, SCRATCH)
            self.asm.bt_reg_reg(resolve(s.base), SCRATCH)
        elif isinstance(s, A.BlastRepFill):
            self._blast_rep_fill(s)
        elif isinstance(s, A.BlastRepCopy):
            self._blast_rep_copy(s)
        elif isinstance(s, A.NetSocket):
            self._net_socket(s)
        elif isinstance(s, A.NetConnect):
            self._net_connect(s)
        elif isinstance(s, A.NetSend):
            self._net_send(s)
        elif isinstance(s, A.NetRecv):
            self._net_recv(s)
        elif isinstance(s, A.NetClose):
            self._net_close(s)
        elif isinstance(s, A.NetPoll):
            self._net_poll(s)
        elif isinstance(s, A.NetEpollCreate):
            self._net_epoll_create(s)
        elif isinstance(s, A.NetEpollCtl):
            self._net_epoll_ctl(s)
        elif isinstance(s, A.NetEpollWait):
            self._net_epoll_wait(s)
        elif isinstance(s, A.StructDef):
            pass  # already collected
        elif isinstance(s, A.FnDef):
            self._emit_fn(s)
        elif isinstance(s, A.LocalDecl):
            pass  # handled inside fn
        elif isinstance(s, A.CpuImul3):
            self.asm.imul_reg_reg_imm(resolve(s.dest), resolve(s.src), s.imm)
        elif isinstance(s, A.CpuMxcsr):
            if s.op == "ld":
                self.asm.ldmxcsr_mem(resolve(s.base))
            else:
                self.asm.stmxcsr_mem(resolve(s.base))
        elif isinstance(s, A.CpuFx):
            if s.op == "save":
                self.asm.fxsave_mem(resolve(s.base))
            else:
                self.asm.fxrstor_mem(resolve(s.base))
        elif isinstance(s, A.CpuXgetbv):
            self.asm.xgetbv()
        elif isinstance(s, A.CpuFsGs):
            getattr(self.asm, s.op + "_reg")(resolve(s.reg))
        elif isinstance(s, A.CpuPrivOp):
            # some take reg, some none
            if s.op in ("sldt", "str", "smsw"):
                getattr(self.asm, s.op + "_reg")(resolve(s.reg))
            else:
                getattr(self.asm, s.op)()
        elif isinstance(s, A.CpuMovzx):
            if s.width == 16:
                self.asm.movzx_r64_r16(resolve(s.dest), resolve(s.src))
            else:
                self.asm.movzx_r64_r8(resolve(s.dest), resolve(s.src))
        elif isinstance(s, A.CpuMovsx):
            if s.width == 16:
                self.asm.movsx_r64_r16(resolve(s.dest), resolve(s.src))
            else:
                self.asm.movsx_r64_r8(resolve(s.dest), resolve(s.src))
        elif isinstance(s, A.CpuBitImm):
            getattr(self.asm, s.op + "_reg_imm8")(resolve(s.base), s.imm)
        elif isinstance(s, A.CpuShldImm):
            self.asm.shld_reg_imm8(resolve(s.dest), resolve(s.src), s.imm)
        elif isinstance(s, A.CpuShrdImm):
            self.asm.shrd_reg_imm8(resolve(s.dest), resolve(s.src), s.imm)
        elif isinstance(s, A.CpuNopLong):
            self.asm.nop_long()
        elif isinstance(s, A.CpuEnter):
            self.asm.enter_imm(s.size, s.nesting)
        elif isinstance(s, A.CpuPext):
            self.asm.pext_reg_reg(resolve(s.dest), resolve(s.src), resolve(s.mask))
        elif isinstance(s, A.CpuPdep):
            self.asm.pdep_reg_reg(resolve(s.dest), resolve(s.src), resolve(s.mask))
        elif isinstance(s, A.CpuMulx):
            self.asm.mulx_reg_reg(resolve(s.dest_hi), resolve(s.dest_lo), resolve(s.src))
        elif isinstance(s, A.CpuCmpxchg):
            self.asm.cmpxchg_reg_reg(resolve(s.dest), resolve(s.src))
        elif isinstance(s, A.CpuPrefetch):
            if s.kind == "w":
                self.asm.prefetchw(resolve(s.base))
            else:
                self.asm.prefetchnta(resolve(s.base))
        elif isinstance(s, A.CpuClflush):
            self.asm.clflush(resolve(s.base))
        elif isinstance(s, A.CpuShlx):
            self.asm.shlx_reg_reg(resolve(s.dest), resolve(s.src), resolve(s.cnt))
        elif isinstance(s, A.CpuShrx):
            self.asm.shrx_reg_reg(resolve(s.dest), resolve(s.src), resolve(s.cnt))
        elif isinstance(s, A.CpuSarx):
            self.asm.sarx_reg_reg(resolve(s.dest), resolve(s.src), resolve(s.cnt))
        elif isinstance(s, A.CpuRorx):
            self.asm.rorx_reg_imm(resolve(s.dest), resolve(s.src), s.imm)
        elif isinstance(s, A.CpuBextr):
            self.asm.bextr_reg_reg(resolve(s.dest), resolve(s.src), resolve(s.ctrl))
        elif isinstance(s, A.CpuBlsi):
            self.asm.blsi_reg_reg(resolve(s.dest), resolve(s.src))
        elif isinstance(s, A.CpuBlsr):
            self.asm.blsr_reg_reg(resolve(s.dest), resolve(s.src))
        elif isinstance(s, A.CpuBlsmsk):
            self.asm.blsmsk_reg_reg(resolve(s.dest), resolve(s.src))
        elif isinstance(s, A.CpuAdcx):
            self.asm.adcx_reg_reg(resolve(s.dest), resolve(s.src))
        elif isinstance(s, A.CpuAdox):
            self.asm.adox_reg_reg(resolve(s.dest), resolve(s.src))
        elif isinstance(s, A.CpuCrc32):
            self.asm.crc32_reg_reg(resolve(s.dest), resolve(s.src))
        elif isinstance(s, A.CpuRdrand):
            self.asm.rdrand_reg(resolve(s.dest))
        elif isinstance(s, A.CpuRdseed):
            self.asm.rdseed_reg(resolve(s.dest))
        elif isinstance(s, A.CpuMovsxd):
            self.asm.movsxd_reg_reg(resolve(s.dest), resolve(s.src))
        elif isinstance(s, A.CpuAdc):
            self.asm.adc_reg_reg(resolve(s.dest), resolve(s.src))
        elif isinstance(s, A.CpuSbb):
            self.asm.sbb_reg_reg(resolve(s.dest), resolve(s.src))
        elif isinstance(s, A.CpuBswap):
            self.asm.bswap_reg(resolve(s.dest))
        elif isinstance(s, A.CpuFlagOp):
            getattr(self.asm, s.op)()
        elif isinstance(s, A.CpuMulDiv1):
            if s.op == "mul":
                self.asm.mul_reg(resolve(s.src))
            else:
                self.asm.div_reg(resolve(s.src))
        elif isinstance(s, A.CpuTestImm):
            self.asm.test_reg_imm32(resolve(s.dest), s.imm)
        elif isinstance(s, A.CpuBitOp):
            getattr(self.asm, s.op + "_reg_reg")(resolve(s.base), resolve(s.offset))
        elif isinstance(s, A.CpuPopcnt):
            self.asm.popcnt_reg_reg(resolve(s.dest), resolve(s.src))
        elif isinstance(s, A.CpuLzcnt):
            self.asm.lzcnt_reg_reg(resolve(s.dest), resolve(s.src))
        elif isinstance(s, A.CpuTzcnt):
            self.asm.tzcnt_reg_reg(resolve(s.dest), resolve(s.src))
        elif isinstance(s, A.CpuShld):
            # SHLD dest, src, CL — user must set rcx/CL; do NOT clobber with src
            self.asm.shld_reg_reg(resolve(s.dest), resolve(s.src))
        elif isinstance(s, A.CpuShrd):
            self.asm.shrd_reg_reg(resolve(s.dest), resolve(s.src))
        elif isinstance(s, A.CpuImulImm):
            self.asm.imul_reg_imm(resolve(s.dest), s.imm)
        elif isinstance(s, A.CpuAndn):
            self.asm.andn_reg_reg(resolve(s.dest), resolve(s.src1), resolve(s.src2))
        elif isinstance(s, A.CpuBzhi):
            self.asm.bzhi_reg_reg(resolve(s.dest), resolve(s.src), resolve(s.ctrl))
        elif isinstance(s, A.CpuCmpxchg16b):
            base = self._base_reg(s.base)
            self.asm.cmpxchg16b_mem(base, s.offset)
        elif isinstance(s, A.CpuCmovMem):
            base = self._base_reg(s.base)
            self.asm.cmov_reg_mem(s.cond, resolve(s.dest), base, s.offset)
        elif isinstance(s, A.PrefixedOp):
            if s.prefix == "lock":
                self.asm.lock_prefix()
            elif s.prefix == "rep":
                self.asm.rep_prefix()
        elif isinstance(s, A.RetVal):
            if s.value is not None:
                self._eval(s.value, "rax")
            if self.in_fn:
                self._fn_epilogue()
            else:
                self.asm.ret()
        elif isinstance(s, A.TargetBaremetal):
            self.baremetal = True
        else:
            raise CodegenError(f"unsupported node {type(s).__name__}")

    def _cpu_bin(self, s: A.CpuBin):
        is_local = s.dest in self.fn_locals
        if is_local:
            off = self.fn_locals[s.dest]
            dst = "r11"
            if s.op != "set":
                self.asm.mov_reg_mem(dst, "rbp", off)
        else:
            dst = resolve(s.dest)
        if s.op == "set":
            self._eval(s.value, dst)
            if is_local:
                self.asm.mov_mem_reg("rbp", off, dst)
            return
        # Use r12 inside frames (SCRATCH is rbp); otherwise SCRATCH is fine
        valreg = "r12" if is_local else SCRATCH
        self._eval(s.value, valreg)
        op = s.op
        if op == "add":
            self.asm.add_reg_reg(dst, valreg)
        elif op == "sub":
            self.asm.sub_reg_reg(dst, valreg)
        elif op == "and":
            self.asm.and_reg_reg(dst, valreg)
        elif op == "or":
            self.asm.or_reg_reg(dst, valreg)
        elif op == "xor":
            self.asm.xor_reg_reg(dst, valreg)
        elif op == "mul":
            self.asm.imul_reg_reg(dst, valreg)
        elif op in ("shl", "shr", "sar", "sal", "rol", "ror", "rcl", "rcr"):
            if isinstance(s.value, A.Number):
                getattr(self.asm, f"{op}_reg_imm8")(dst, s.value.value & 63)
            else:
                if op in ("rcl", "rcr"):
                    pass  # have _reg_cl now
                if dst == "rcx":
                    self.asm.push_reg("rax")
                    self.asm.mov_reg_reg("rax", "rcx")
                    self.asm.mov_reg_reg("rcx", valreg)
                    getattr(self.asm, f"{op}_reg_cl")("rax")
                    self.asm.mov_reg_reg("rcx", "rax")
                    self.asm.pop_reg("rax")
                else:
                    self.asm.push_reg("rcx")
                    self.asm.mov_reg_reg("rcx", valreg)
                    getattr(self.asm, f"{op}_reg_cl")(dst)
                    self.asm.pop_reg("rcx")
        elif op in ("div", "mod"):
            self.asm.push_reg("rax")
            self.asm.push_reg("rdx")
            self.asm.mov_reg_reg("rax", dst)
            self.asm.cqo()
            self.asm.idiv_reg(valreg)
            result = "rdx" if op == "mod" else "rax"
            self.asm.mov_reg_reg(valreg, result)
            self.asm.pop_reg("rdx")
            self.asm.pop_reg("rax")
            self.asm.mov_reg_reg(dst, valreg)
        else:
            raise CodegenError(f"cpu:{op} not implemented")
        if is_local:
            self.asm.mov_mem_reg("rbp", off, dst)


    def _cpu_unary(self, s: A.CpuUnary):
        is_local = s.dest in self.fn_locals
        if is_local:
            off = self.fn_locals[s.dest]
            dst = "r11"
            self.asm.mov_reg_mem(dst, "rbp", off)
        else:
            dst = resolve(s.dest)
        if s.op == "not":
            self.asm.not_reg(dst)
        elif s.op == "neg":
            self.asm.neg_reg(dst)
        elif s.op == "inc":
            self.asm.inc_reg(dst)
        elif s.op == "dec":
            self.asm.dec_reg(dst)
        else:
            raise CodegenError(f"cpu:{s.op}")
        if is_local:
            self.asm.mov_mem_reg("rbp", off, dst)

    def _base_reg(self, base: Any) -> str:
        if isinstance(base, A.Reg):
            return resolve(base.name)
        if isinstance(base, A.Ident):
            if base.name in self.fn_locals:
                off = self.fn_locals[base.name]
                self.asm.mov_reg_mem("r13", "rbp", off)
                return "r13"
            # Prefer r11 over SCRATCH(=rbp) so frames stay intact
            self.asm.lea_reg_label("r11", f"__data_{base.name}")
            return "r11"
        raise CodegenError("bad memory base")


    def _resolve_offset(self, off) -> int:
        if isinstance(off, int):
            return off
        if isinstance(off, A.Number):
            return off.value
        if isinstance(off, A.StructFieldRef):
            if off.struct not in self.structs:
                raise CodegenError(f"unknown struct '{off.struct}'")
            fields = self.structs[off.struct]["fields"]
            if off.field not in fields:
                raise CodegenError(f"unknown field '{off.struct}.{off.field}'")
            return fields[off.field]
        if isinstance(off, A.BinExpr):
            l = self._resolve_offset(off.left)
            r = self._resolve_offset(off.right)
            if off.op == "+":
                return l + r
            if off.op == "-":
                return l - r
            if off.op == "*":
                return l * r
            raise CodegenError(f"bad offset op {off.op}")
        raise CodegenError(f"non-constant memory offset {type(off).__name__}")

    def _mem_load(self, s: A.MemLoad):
        base = self._base_reg(s.base)
        off = self._resolve_offset(s.offset)
        is_local = s.dest in self.fn_locals
        if is_local:
            dst = "r12"
        else:
            dst = resolve(s.dest)
        idx = None
        if getattr(s, "index", None) is not None:
            if isinstance(s.index, A.Reg):
                idx = resolve(s.index.name)
            else:
                self._eval(s.index, "r13")
                idx = "r13"
        sc = getattr(s, "scale", 1) or 1
        if s.size == 8:
            self.asm.mov8_reg_mem(dst, base, off, idx, sc)
        elif s.size == 16:
            self.asm.mov16_reg_mem(dst, base, off, idx, sc)
        elif s.size == 32:
            self.asm.mov32_reg_mem(dst, base, off, idx, sc)
        else:
            self.asm.mov_reg_mem(dst, base, off, idx, sc)
        if is_local:
            loff = self.fn_locals[s.dest]
            self.asm.mov_mem_reg("rbp", loff, dst)

    def _mem_store(self, s: A.MemStore):
        self.asm.push_reg("r12")
        # Eval value straight into r12 — never use SCRATCH(=rbp) inside frames
        self._eval(s.value, "r12")
        base = self._base_reg(s.base)
        off = self._resolve_offset(s.offset)
        idx = None
        if getattr(s, "index", None) is not None:
            if isinstance(s.index, A.Reg):
                idx = resolve(s.index.name)
            else:
                self._eval(s.index, "r13")
                idx = "r13"
        sc = getattr(s, "scale", 1) or 1
        if s.size == 8:
            self.asm.mov8_mem_reg(base, off, "r12", idx, sc)
        elif s.size == 16:
            self.asm.mov16_mem_reg(base, off, "r12", idx, sc)
        elif s.size == 32:
            self.asm.mov32_mem_reg(base, off, "r12", idx, sc)
        else:
            self.asm.mov_mem_reg(base, off, "r12", idx, sc)
        self.asm.pop_reg("r12")

    def _syscall(self, s: A.SysCall):
        if self.baremetal:
            raise CodegenError(
                "sys:call is Linux-userland only; not valid in target:baremetal / freestanding kernel. "
                "Use chip:halt, chip:cli, port:in/out, or raw: sequences."
            )
        if isinstance(s.num, A.Number):
            num = s.num.value
        else:
            name = str(s.num).lower()
            if name not in NAMED_SYSCALLS:
                raise CodegenError(f"unknown syscall '{name}'")
            num = NAMED_SYSCALLS[name]
        for arg in s.args[:6]:
            self._eval(arg, SCRATCH)
            self.asm.push_reg(SCRATCH)
        for i in range(len(s.args[:6]) - 1, -1, -1):
            self.asm.pop_reg(SYSCALL_ARGS[i])
        self.asm.mov_reg_imm64("rax", num)
        # Linux x86-64 syscall clobbers RCX (return RIP) and R11 (RFLAGS).
        # Preserve them so virtual reg3 (rcx) is not silently destroyed.
        self.asm.push_reg("rcx")
        self.asm.push_reg("r11")
        self.asm.syscall()
        self.asm.pop_reg("r11")
        self.asm.pop_reg("rcx")

    def _blast_fill(self, s: A.BlastFill):
        dest = resolve(s.dest)
        for r in ("r11", "r12", "r13"):
            self.asm.push_reg(r)
        self.asm.mov_reg_reg("r11", dest)
        self._eval(s.byte_val, SCRATCH)
        self.asm.mov_reg_reg("r12", SCRATCH)
        self._eval(s.length, SCRATCH)
        self.asm.mov_reg_reg("r13", SCRATCH)
        loop = self.new_label("fill")
        done = self.new_label("filld")
        self.asm.label(loop)
        self.asm.test_reg_reg("r13", "r13")
        self.asm.jcc("eq", done)
        self.asm.mov8_mem_reg("r11", 0, "r12")
        self.asm.add_reg_imm("r11", 1)
        self.asm.sub_reg_imm("r13", 1)
        self.asm.jmp(loop)
        self.asm.label(done)
        self.asm.pop_reg("r13")
        self.asm.pop_reg("r12")
        self.asm.pop_reg("r11")

    def _blast_copy(self, s: A.BlastCopy):
        dest = resolve(s.dest)
        for r in ("r11", "r12", "r13"):
            self.asm.push_reg(r)
        self.asm.mov_reg_reg("r11", dest)
        self._eval(s.src, SCRATCH)
        self.asm.mov_reg_reg("r12", SCRATCH)
        self._eval(s.length, SCRATCH)
        self.asm.mov_reg_reg("r13", SCRATCH)
        loop = self.new_label("copy")
        done = self.new_label("copyd")
        self.asm.label(loop)
        self.asm.test_reg_reg("r13", "r13")
        self.asm.jcc("eq", done)
        self.asm.mov8_reg_mem(SCRATCH, "r12", 0)
        self.asm.mov8_mem_reg("r11", 0, SCRATCH)
        self.asm.add_reg_imm("r11", 1)
        self.asm.add_reg_imm("r12", 1)
        self.asm.sub_reg_imm("r13", 1)
        self.asm.jmp(loop)
        self.asm.label(done)
        self.asm.pop_reg("r13")
        self.asm.pop_reg("r12")
        self.asm.pop_reg("r11")

    def _wire_len(self, s: A.WireLen):
        dest = resolve(s.dest)
        self.asm.push_reg("r11")
        self._eval(s.src, SCRATCH)
        self.asm.mov_reg_reg("r11", SCRATCH)
        self.asm.xor_reg_reg(dest, dest)
        loop = self.new_label("wlen")
        done = self.new_label("wlend")
        self.asm.label(loop)
        self.asm.mov8_reg_mem(SCRATCH, "r11", 0)
        self.asm.test_reg_reg(SCRATCH, SCRATCH)
        self.asm.jcc("eq", done)
        self.asm.inc_reg(dest)
        self.asm.add_reg_imm("r11", 1)
        self.asm.jmp(loop)
        self.asm.label(done)
        self.asm.pop_reg("r11")

    def _wire_cmp(self, s: A.WireCmp):
        """Return 0 if equal, 1 if different (byte-wise until NUL)."""
        dest = resolve(s.dest)
        self.asm.push_reg("r11")
        self.asm.push_reg("r12")
        self.asm.push_reg("r13")
        self._eval(s.left, SCRATCH)
        self.asm.mov_reg_reg("r11", SCRATCH)
        self._eval(s.right, SCRATCH)
        self.asm.mov_reg_reg("r12", SCRATCH)
        loop = self.new_label("wcmp")
        eq = self.new_label("wcmpeq")
        ne = self.new_label("wcmpne")
        done = self.new_label("wcmpd")
        self.asm.label(loop)
        self.asm.mov8_reg_mem("r13", "r11", 0)
        self.asm.mov8_reg_mem(SCRATCH, "r12", 0)
        self.asm.cmp_reg_reg("r13", SCRATCH)
        self.asm.jcc("neq", ne)
        self.asm.test_reg_reg("r13", "r13")
        self.asm.jcc("eq", eq)
        self.asm.add_reg_imm("r11", 1)
        self.asm.add_reg_imm("r12", 1)
        self.asm.jmp(loop)
        self.asm.label(eq)
        self.asm.xor_reg_reg(dest, dest)
        self.asm.jmp(done)
        self.asm.label(ne)
        self.asm.mov_reg_imm64(dest, 1)
        self.asm.label(done)
        self.asm.pop_reg("r13")
        self.asm.pop_reg("r12")
        self.asm.pop_reg("r11")

    def _wire_copy(self, s: A.WireCopy):
        self.asm.push_reg("r11")
        self.asm.push_reg("r12")
        self._eval(s.dest, SCRATCH)
        self.asm.mov_reg_reg("r11", SCRATCH)
        self._eval(s.src, SCRATCH)
        self.asm.mov_reg_reg("r12", SCRATCH)
        loop = self.new_label("wcpy")
        done = self.new_label("wcpyd")
        self.asm.label(loop)
        self.asm.mov8_reg_mem(SCRATCH, "r12", 0)
        self.asm.mov8_mem_reg("r11", 0, SCRATCH)
        self.asm.test_reg_reg(SCRATCH, SCRATCH)
        self.asm.jcc("eq", done)
        self.asm.add_reg_imm("r11", 1)
        self.asm.add_reg_imm("r12", 1)
        self.asm.jmp(loop)
        self.asm.label(done)
        self.asm.pop_reg("r12")
        self.asm.pop_reg("r11")

    def _wire_emit(self, s: A.WireEmit):
        """sys_write(1, src, len). If len omitted, compute NUL-terminated length."""
        self.asm.push_reg("r11")
        self._eval(s.src, SCRATCH)
        self.asm.mov_reg_reg("r11", SCRATCH)
        if s.length is not None:
            self._eval(s.length, SCRATCH)
            self.asm.mov_reg_reg("rdx", SCRATCH)
        else:
            self.asm.xor_reg_reg("rdx", "rdx")
            loop = self.new_label("weml")
            done = self.new_label("wemld")
            self.asm.label(loop)
            self.asm.mov8_reg_mem(SCRATCH, "r11", 0)
            self.asm.test_reg_reg(SCRATCH, SCRATCH)
            self.asm.jcc("eq", done)
            self.asm.inc_reg("rdx")
            self.asm.add_reg_imm("r11", 1)
            self.asm.jmp(loop)
            self.asm.label(done)
            self._eval(s.src, SCRATCH)
            self.asm.mov_reg_reg("r11", SCRATCH)
        self.asm.mov_reg_imm64("rax", 1)  # write
        self.asm.mov_reg_imm64("rdi", 1)  # stdout
        self.asm.mov_reg_reg("rsi", "r11")
        self.asm.syscall()
        self.asm.pop_reg("r11")


    def _cell_mapfile(self, s: A.CellMapFile):
        # mmap file-backed: flags MAP_PRIVATE=2, fd, offset
        for r in ("r12", "r13", "r14", "rbx"):
            self.asm.push_reg(r)
        self._eval(s.size, "r12")
        self._eval(s.fd, "r13")
        if s.offset is not None:
            self._eval(s.offset, "r14")
        else:
            self.asm.xor_reg_reg("r14", "r14")
        if s.prot is not None:
            self._eval(s.prot, "rbx")
        else:
            self.asm.mov_reg_imm64("rbx", 3)  # RW
        self.asm.xor_reg_reg("rdi", "rdi")
        self.asm.mov_reg_reg("rsi", "r12")
        self.asm.mov_reg_reg("rdx", "rbx")
        self.asm.mov_reg_imm64("r10", 2)  # MAP_PRIVATE
        self.asm.mov_reg_reg("r8", "r13")  # fd
        self.asm.mov_reg_reg("r9", "r14")  # offset
        self.asm.mov_reg_imm64("rax", 9)
        self.asm.syscall()
        dst = resolve(s.dest)
        if dst != "rax":
            self.asm.mov_reg_reg(dst, "rax")
        self.asm.pop_reg("rbx")
        self.asm.pop_reg("r14")
        self.asm.pop_reg("r13")
        self.asm.pop_reg("r12")

    def _net_poll(self, s: A.NetPoll):
        for r in ("r12", "r13", "r14"):
            self.asm.push_reg(r)
        self._eval(s.fds, "r12")
        self._eval(s.nfds, "r13")
        self._eval(s.timeout, "r14")
        self.asm.mov_reg_reg("rdi", "r12")
        self.asm.mov_reg_reg("rsi", "r13")
        self.asm.mov_reg_reg("rdx", "r14")
        self.asm.mov_reg_imm64("rax", 7)  # poll
        self.asm.syscall()
        self.asm.pop_reg("r14")
        self.asm.pop_reg("r13")
        self.asm.pop_reg("r12")

    def _net_epoll_create(self, s: A.NetEpollCreate):
        if s.flags is not None:
            self._eval(s.flags, "rdi")
        else:
            self.asm.xor_reg_reg("rdi", "rdi")
        self.asm.mov_reg_imm64("rax", 291)  # epoll_create1
        self.asm.syscall()
        dst = resolve(s.dest)
        if dst != "rax":
            self.asm.mov_reg_reg(dst, "rax")

    def _net_epoll_ctl(self, s: A.NetEpollCtl):
        for r in ("r12", "r13", "r14", "rbx"):
            self.asm.push_reg(r)
        self._eval(s.epfd, "r12")
        self._eval(s.op, "r13")
        self._eval(s.fd, "r14")
        self._eval(s.event_ptr, "rbx")
        self.asm.mov_reg_reg("rdi", "r12")
        self.asm.mov_reg_reg("rsi", "r13")
        self.asm.mov_reg_reg("rdx", "r14")
        self.asm.mov_reg_reg("r10", "rbx")
        self.asm.mov_reg_imm64("rax", 233)
        self.asm.syscall()
        self.asm.pop_reg("rbx")
        self.asm.pop_reg("r14")
        self.asm.pop_reg("r13")
        self.asm.pop_reg("r12")

    def _net_epoll_wait(self, s: A.NetEpollWait):
        for r in ("r12", "r13", "r14", "rbx"):
            self.asm.push_reg(r)
        self._eval(s.epfd, "r12")
        self._eval(s.events, "r13")
        self._eval(s.maxevents, "r14")
        self._eval(s.timeout, "rbx")
        self.asm.mov_reg_reg("rdi", "r12")
        self.asm.mov_reg_reg("rsi", "r13")
        self.asm.mov_reg_reg("rdx", "r14")
        self.asm.mov_reg_reg("r10", "rbx")
        self.asm.mov_reg_imm64("rax", 232)
        self.asm.syscall()
        dst = resolve(s.dest)
        if dst != "rax":
            self.asm.mov_reg_reg(dst, "rax")
        self.asm.pop_reg("rbx")
        self.asm.pop_reg("r14")
        self.asm.pop_reg("r13")
        self.asm.pop_reg("r12")

    def _cell_map(self, s: A.CellMap):
        # Clobber-safe: push temps, eval onto stack, then syscall regs
        for r in ("r12", "r13", "r14"):
            self.asm.push_reg(r)
        self._eval(s.size, "r12")
        if s.prot is not None:
            self._eval(s.prot, "r13")
        else:
            self.asm.mov_reg_imm64("r13", 3)
        if s.flags is not None:
            self._eval(s.flags, "r14")
        else:
            self.asm.mov_reg_imm64("r14", 0x22)
        self.asm.xor_reg_reg("rdi", "rdi")
        self.asm.mov_reg_reg("rsi", "r12")
        self.asm.mov_reg_reg("rdx", "r13")
        self.asm.mov_reg_reg("r10", "r14")
        self.asm.mov_reg_imm64("r8", 0xFFFFFFFFFFFFFFFF)
        self.asm.xor_reg_reg("r9", "r9")
        self.asm.mov_reg_imm64("rax", 9)
        self.asm.syscall()
        dst = resolve(s.dest)
        if dst != "rax":
            self.asm.mov_reg_reg(dst, "rax")
        self.asm.pop_reg("r14")
        self.asm.pop_reg("r13")
        self.asm.pop_reg("r12")

    def _cell_free(self, s: A.CellFree):
        # Evaluate both operands before fixed syscall registers are set.
        self._eval(s.ptr, SCRATCH)
        self.asm.push_reg(SCRATCH)          # save ptr
        self._eval(s.size, SCRATCH)
        self.asm.mov_reg_reg("rsi", SCRATCH)
        self.asm.pop_reg("rdi")             # ptr → rdi
        self.asm.mov_reg_imm64("rax", 11)
        self.asm.syscall()

    def _gate_cas(self, s: A.GateCas):
        addr = resolve(s.addr)
        exp = resolve(s.expected)
        des = resolve(s.desired)
        self.asm.mov_reg_reg("r11", addr)
        # preserve caller's rax when neither addr nor expected is rax
        save_rax = (addr != "rax" and exp != "rax")
        if save_rax:
            self.asm.mov_reg_reg("r13", "rax")
        if des in ("rax", "r11", "r13"):
            self.asm.mov_reg_reg("r12", des)
            des_r = "r12"
        else:
            des_r = des
        if exp != "rax":
            self.asm.mov_reg_reg("rax", exp)
        self.asm.lock_cmpxchg_mem("r11", 0, des_r)
        if exp != "rax":
            self.asm.mov_reg_reg(exp, "rax")
        if addr == "rax":
            self.asm.mov_reg_reg("rax", "r11")
        elif save_rax:
            self.asm.mov_reg_reg("rax", "r13")

    def _gate_spin(self, s: A.GateSpin):
        addr = resolve(s.addr)
        self.asm.mov_reg_reg("r11", addr)
        save_rax = addr != "rax"
        if save_rax:
            self.asm.mov_reg_reg("r13", "rax")
        loop = self.new_label("spin")
        self.asm.label(loop)
        self.asm.xor_reg_reg("rax", "rax")
        self.asm.mov_reg_imm64("r12", 1)
        self.asm.lock_cmpxchg_mem("r11", 0, "r12")
        self.asm.jcc("neq", loop)
        if addr == "rax":
            self.asm.mov_reg_reg("rax", "r11")
        elif save_rax:
            self.asm.mov_reg_reg("rax", "r13")

    def _pulse_sleep(self, s: A.PulseSleep):
        # timespec: sec=0, nsec=<ns> (use ns < 1e9)
        self.asm.lea_reg_label("rdi", "__data___timespec")
        self.asm.xor_reg_reg("rax", "rax")
        self.asm.mov_mem_reg("rdi", 0, "rax")
        self._eval(s.ns, "rax")
        self.asm.mov_mem_reg("rdi", 8, "rax")
        self.asm.xor_reg_reg("rsi", "rsi")
        self.asm.mov_reg_imm64("rax", 35)
        self.asm.syscall()

    def _pulse_now(self, s: A.PulseNow):
        self.asm.mov_reg_imm64("rdi", 1)  # CLOCK_MONOTONIC
        self.asm.lea_reg_label("rsi", "__data___timespec")
        self.asm.mov_reg_imm64("rax", 228)
        self.asm.syscall()
        self.asm.lea_reg_label("r11", "__data___timespec")
        self.asm.mov_reg_mem(resolve(s.dest), "r11", 0)

    def _base_phys(self, base) -> str:
        if isinstance(base, A.Reg):
            return resolve(base.name)
        if isinstance(base, A.Ident):
            # load address of label into r12
            self.asm.lea_reg_label("r12", f"__data_{base.name}")
            return "r12"
        if isinstance(base, A.Number):
            self.asm.mov_reg_imm64("r12", base.value)
            return "r12"
        raise CodegenError(f"bad base {type(base)}")

    def _vec_load(self, s: A.VecLoad):
        base = self._base_phys(s.base)
        self.asm.movups_xmm_mem(s.xmm, base, s.offset)

    def _vec_store(self, s: A.VecStore):
        base = self._base_phys(s.base)
        self.asm.movups_mem_xmm(base, s.xmm, s.offset)


    def _cpu_test(self, s: A.CpuTest):
        """test left, right — sets flags, no dest write."""
        self._eval(s.left, "r11")
        self._eval(s.right, "r12")
        self.asm.test_reg_reg("r11", "r12")


    def _run_asserts(self, code_b: bytes, data_b: bytes):
        for name, limit, op, off in getattr(self, "_assert_bytes", []):
            # size from named label if present else from off to end
            start = self.asm.labels.get(f"__lbl_{name}", self.asm.labels.get(name, 0))
            size = off - start if off >= start else len(code_b)
            if op == "eq" and size != limit:
                raise CodegenError(f"assert:bytes {name}: got {size} bytes, want == {limit}")
            if op == "le" and size > limit:
                raise CodegenError(f"assert:bytes {name}: got {size} bytes, want <= {limit}")
        for what, limit in getattr(self, "_assert_sizes", []):
            n = len(code_b) if what == "code" else len(data_b)
            if n > limit:
                raise CodegenError(f"assert:size {what}: got {n} bytes, want <= {limit}")

    def _build_listing(self, code_b: bytes):
        """Hex dump; in teach mode also map source lines → bytes + hint + flags."""
        self._listing_lines.append("; ACLM listing" + (" [TEACH]" if self.teach_mode else ""))
        self._listing_lines.append("; virtual→physical: reg1=rax reg2=rbx reg3=rcx reg4=rdx reg5=rsi reg6=rdi")
        self._listing_lines.append(";   reg7=r8 reg8=r9 reg9=r10 reg10=r11 reg11=r12 reg12=r13 reg13=r14 SCRATCH=r15")
        self._listing_lines.append("; flags: ADD/SUB/CMP/TEST write SZAPC; MOV/LEA/MOVZX intact; SETcc reads flags")
        if self.deterministic:
            self._listing_lines.append("; mode: deterministic encodings")
        for h in getattr(self, "_section_hints", []):
            self._listing_lines.append(f"; {h}")
        for block in getattr(self, "_frame_diagrams", []):
            self._listing_lines.append(block)
        if self.structs:
            for sn, si in self.structs.items():
                fields = ", ".join(f"{f}@+{o}" for f, o in si["fields"].items())
                self._listing_lines.append(f"; struct {sn} size={si['size']}: {fields}")
        if self.teach_mode and self._teach_map:
            # group code ranges by statement
            spans = []
            for i, (line, hint, start) in enumerate(self._teach_map):
                end = self._teach_map[i + 1][2] if i + 1 < len(self._teach_map) else len(code_b)
                spans.append((line, hint, start, end))
            for line, hint, start, end in spans:
                if end <= start:
                    continue
                chunk = code_b[start:end]
                hexs = " ".join(f"{b:02x}" for b in chunk)
                # mnemonic hint from node type
                mnem = self._teach_mnemonic(hint, chunk)
                self._listing_lines.append(f"; L{line}  {hint}")
                self._listing_lines.append(f"{start:08x}: {hexs}")
                if mnem:
                    self._listing_lines.append(f"         ; → {mnem}")
            self._listing_lines.append(";")
            self._listing_lines.append("; --- full hex dump ---")
        for i in range(0, len(code_b), 16):
            chunk = code_b[i:i+16]
            hexs = " ".join(f"{b:02x}" for b in chunk)
            self._listing_lines.append(f"{i:08x}: {hexs}")

    def _teach_mnemonic(self, hint: str, chunk: bytes) -> str:
        """Best-effort teaching annotation from AST node name + first bytes."""
        table = {
            "CpuBin": "alu/mov (cpu:set/add/sub/...)",
            "CpuUnary": "unary (inc/dec/not/neg)",
            "CpuTest": "test r64, r64  (flags only)",
            "CpuCmov": "cmovcc r64, r64",
            "CpuLea": "lea r64, [mem]",
            "Cmp": "cmp r64, r64",
            "JumpIf": "jcc rel32",
            "Goto": "jmp rel32",
            "Label": "(label — no bytes)",
            "SysCall": "mov eax,imm ; syscall",
            "Call": "call rel32",
            "Ret": "ret",
            "RetVal": "mov rax, val ; ret",
            "MemLoad": "mov r64, [mem]",
            "MemStore": "mov [mem], r64",
            "StackPush": "push r64",
            "StackPop": "pop r64",
            "RawBytes": "raw bytes (exact opcodes)",
            "CellMap": "syscall mmap",
            "CellFree": "syscall munmap",
            "FlagSetcc": "setcc + zext  |  flags:READ",
            "FlagsClear": "cld | DF:=0",
            "FlagsSetDF": "std | DF:=1",
            "CpuMovExt": "movzx/movsx",
            "DataBytes": "data bytes in .data",
            "MetalRegs": "(regs map — listing only)",
            "MetalDeterministic": "(deterministic mode)",
            "CpuLeaRip": "lea r64, [rip+label]",
            "CpuLeaAbs": "movabs r64, imm64 (abs)",
            "AssertBytes": "(compile-time size assert)",
            "AssertSize": "(compile-time size assert)",
        }
        base = table.get(hint, hint)
        if not chunk:
            return base
        b0 = chunk[0]
        extra = []
        if b0 in (0x48, 0x49, 0x4C, 0x4D) and len(chunk) > 1:
            b1 = chunk[1]
            if b1 == 0x89: extra.append("REX mov r/r")
            elif b1 == 0x8B: extra.append("REX mov r/m")
            elif b1 == 0x01: extra.append("REX add")
            elif b1 == 0x29: extra.append("REX sub")
            elif b1 == 0x85: extra.append("REX test")
            elif b1 == 0x39: extra.append("REX cmp")
            elif b1 == 0x8D: extra.append("REX lea")
            elif b1 == 0x0F and len(chunk) > 2:
                extra.append(f"0F {chunk[2]:02x} (cmov/jcc/...)")
        elif b0 == 0xB8: extra.append("mov eax, imm32")
        elif b0 in range(0xB8, 0xC0): extra.append("mov r32, imm32")
        elif b0 == 0xE8: extra.append("call rel32")
        elif b0 == 0xE9: extra.append("jmp rel32")
        elif b0 == 0x0F and len(chunk) > 1 and chunk[1] in (0x84, 0x85, 0x8C, 0x8D, 0x8E, 0x8F):
            extra.append("jcc rel32")
        elif b0 == 0xC3: extra.append("ret")
        elif b0 == 0x55: extra.append("push rbp")
        elif b0 == 0xC9: extra.append("leave")
        if extra:
            return f"{base}  |  {' '.join(extra)}"
        return base

    def _cpu_movext(self, s: A.CpuMovExt):
        """movzx/movsx dest = src (reg only for now; mem via ram:read already zext)."""
        dst = resolve(s.dest)
        if isinstance(s.src, A.Reg):
            src = resolve(s.src.name)
            if s.op == "movsx":
                self.asm.movsx_reg_reg(dst, src, s.size)
            else:
                self.asm.movzx_reg_reg(dst, src, s.size)
        else:
            # evaluate into r12 then extend from low byte/word
            self._eval(s.src, "r12")
            if s.op == "movsx":
                self.asm.movsx_reg_reg(dst, "r12", s.size)
            else:
                self.asm.movzx_reg_reg(dst, "r12", s.size)

    def _cpu_lea(self, s: A.CpuLea):
        dst = resolve(s.dest)
        if isinstance(s.base, A.Ident) and s.index is None and s.offset == 0:
            self.asm.lea_reg_label(dst, f"__data_{s.base.name}")
            return
        base = self._base_phys(s.base)
        idx = None
        if s.index is not None:
            if isinstance(s.index, A.Reg):
                idx = resolve(s.index.name)
            else:
                self._eval(s.index, "r13")
                idx = "r13"
        self.asm.lea_reg_mem(dst, base, s.offset, idx, s.scale)

    def _thread_spawn(self, s: A.ThreadSpawn):
        # mmap stack + clone; child signals by xadd on done_count
        self.asm.xor_reg_reg("rdi", "rdi")
        self.asm.mov_reg_imm64("rsi", 1 << 20)
        self.asm.mov_reg_imm64("rdx", 3)
        self.asm.mov_reg_imm64("r10", 0x22)
        self.asm.mov_reg_imm64("r8", 0xFFFFFFFFFFFFFFFF)
        self.asm.xor_reg_reg("r9", "r9")
        self.asm.mov_reg_imm64("rax", 9)
        self.asm.syscall()
        self.asm.mov_reg_reg("r12", "rax")
        self.asm.add_reg_imm("r12", (1 << 20) - 16)
        self.asm.mov_reg_imm64("rdi", 0x00000F00)
        self.asm.mov_reg_reg("rsi", "r12")
        self.asm.xor_reg_reg("rdx", "rdx")
        self.asm.xor_reg_reg("r10", "r10")
        self.asm.xor_reg_reg("r8", "r8")
        self.asm.mov_reg_imm64("rax", 56)
        self.asm.syscall()
        child = self.new_label("thr_c")
        parent = self.new_label("thr_p")
        self.asm.test_reg_reg("rax", "rax")
        self.asm.jcc("eq", child)
        dst = resolve(s.dest)
        if dst != "rax":
            self.asm.mov_reg_reg(dst, "rax")
        # spawn_count++ at __thr_futex+16
        self.asm.push_reg("rax")
        self.asm.lea_reg_label("rdi", "__data___thr_futex")
        self.asm.mov_reg_mem("rax", "rdi", 16)
        self.asm.add_reg_imm("rax", 1)
        self.asm.mov_mem_reg("rdi", 16, "rax")
        self.asm.pop_reg("rax")
        self.asm.jmp(parent)
        self.asm.label(child)
        self.asm.call(f"__lbl_{s.label}")
        # done_count++
        self.asm.lea_reg_label("rdi", "__data___thr_futex")
        self.asm.mov_reg_mem("rax", "rdi", 0)
        self.asm.add_reg_imm("rax", 1)
        self.asm.mov_mem_reg("rdi", 0, "rax")
        self.asm.mov_reg_imm64("rsi", 1)
        self.asm.mov_reg_imm64("rdx", 1)
        self.asm.mov_reg_imm64("rax", 202)
        self.asm.syscall()
        self.asm.xor_reg_reg("rdi", "rdi")
        self.asm.mov_reg_imm64("rax", 60)
        self.asm.syscall()
        self.asm.label(parent)

    def _thread_join(self, s: A.ThreadJoin):
        # Wait until done_count > joined_count; then joined_count++
        loop = self.new_label("jw")
        done = self.new_label("jd")
        self.asm.mov_reg_imm64("r14", 200000)
        self.asm.label(loop)
        self.asm.lea_reg_label("rdi", "__data___thr_futex")
        self.asm.mov_reg_mem("rax", "rdi", 0)   # done
        self.asm.mov_reg_mem("rcx", "rdi", 8)   # joined
        self.asm.cmp_reg_reg("rax", "rcx")
        self.asm.jcc("gt", done)  # done > joined (unsigned above)
        # also try CF via above
        self.asm.cmp_reg_reg("rcx", "rax")
        self.asm.jcc("below", done)  # joined < done
        self.asm.lea_reg_label("rdi", "__data___thr_futex")
        self.asm.xor_reg_reg("rsi", "rsi")
        self.asm.mov_reg_mem("rdx", "rdi", 0)  # expected done
        self.asm.xor_reg_reg("r10", "r10")
        self.asm.mov_reg_imm64("rax", 202)
        self.asm.syscall()
        self.asm.dec_reg("r14")
        self.asm.test_reg_reg("r14", "r14")
        self.asm.jcc("eq", done)
        self.asm.jmp(loop)
        self.asm.label(done)
        # joined++
        self.asm.lea_reg_label("rdi", "__data___thr_futex")
        self.asm.mov_reg_mem("rax", "rdi", 8)
        self.asm.add_reg_imm("rax", 1)
        self.asm.mov_mem_reg("rdi", 8, "rax")


    def _thread_join_all(self, s: A.ThreadJoinAll):
        # Wait until done_count >= spawn_count
        loop = self.new_label("ja_w")
        done = self.new_label("ja_d")
        self.asm.mov_reg_imm64("r14", 500000)
        self.asm.label(loop)
        self.asm.lea_reg_label("rdi", "__data___thr_futex")
        self.asm.mov_reg_mem("rax", "rdi", 0)   # done
        self.asm.mov_reg_mem("rcx", "rdi", 16)  # spawn_count
        self.asm.cmp_reg_reg("rax", "rcx")
        self.asm.jcc("abe", done)  # done >= spawn
        self.asm.xor_reg_reg("rsi", "rsi")
        self.asm.mov_reg_mem("rdx", "rdi", 0)
        self.asm.xor_reg_reg("r10", "r10")
        self.asm.mov_reg_imm64("rax", 202)
        self.asm.syscall()
        self.asm.dec_reg("r14")
        self.asm.test_reg_reg("r14", "r14")
        self.asm.jcc("eq", done)
        self.asm.jmp(loop)
        self.asm.label(done)

    def _thread_exit(self, s: A.ThreadExit):
        # signal completion before dying
        self.asm.lea_reg_label("rdi", "__data___thr_futex")
        self.asm.mov_reg_mem("rax", "rdi", 0)
        self.asm.add_reg_imm("rax", 1)
        self.asm.mov_mem_reg("rdi", 0, "rax")
        self.asm.mov_reg_imm64("rsi", 1)
        self.asm.mov_reg_imm64("rdx", 1)
        self.asm.mov_reg_imm64("rax", 202)
        self.asm.syscall()
        if s.code is not None:
            self._eval(s.code, "rdi")
        else:
            self.asm.xor_reg_reg("rdi", "rdi")
        self.asm.mov_reg_imm64("rax", 60)
        self.asm.syscall()

    def _blast_rep_fill(self, s: A.BlastRepFill):
        # rdi=dest, al=byte, rcx=len ; rep stosb
        # 1. Evaluate all operands into scratches first (clobber-safe).
        # 2. Restore the original dest register after (rep stosb advances
        #    rdi; if dest was rdi the caller expects the original pointer).
        dest = resolve(s.dest)
        for r in ("r11", "r12", "r13"):
            self.asm.push_reg(r)
        self.asm.mov_reg_reg("r11", dest)          # original pointer
        self._eval(s.byte_val, SCRATCH)
        self.asm.mov_reg_reg("r12", SCRATCH)
        self._eval(s.length, SCRATCH)
        self.asm.mov_reg_reg("r13", SCRATCH)
        self.asm.mov_reg_reg("rdi", "r11")
        self.asm.mov_reg_reg("rax", "r12")
        self.asm.mov_reg_reg("rcx", "r13")
        self.asm.rep_stosb()
        if dest != "r11":
            self.asm.mov_reg_reg(dest, "r11")
        self.asm.pop_reg("r13")
        self.asm.pop_reg("r12")
        self.asm.pop_reg("r11")

    def _blast_rep_copy(self, s: A.BlastRepCopy):
        # rdi=dest, rsi=src, rcx=len ; rep movsb
        # Same clobber-safe pattern + restore original dest pointer.
        dest = resolve(s.dest)
        for r in ("r11", "r12", "r13"):
            self.asm.push_reg(r)
        self.asm.mov_reg_reg("r11", dest)          # original pointer
        self._eval(s.src, SCRATCH)
        self.asm.mov_reg_reg("r12", SCRATCH)
        self._eval(s.length, SCRATCH)
        self.asm.mov_reg_reg("r13", SCRATCH)
        self.asm.mov_reg_reg("rdi", "r11")
        self.asm.mov_reg_reg("rsi", "r12")
        self.asm.mov_reg_reg("rcx", "r13")
        self.asm.rep_movsb()
        if dest != "r11":
            self.asm.mov_reg_reg(dest, "r11")
        self.asm.pop_reg("r13")
        self.asm.pop_reg("r12")
        self.asm.pop_reg("r11")

    def _net_socket(self, s: A.NetSocket):
        self._eval(s.domain, "rdi")
        self._eval(s.type_, "rsi")
        self._eval(s.protocol, "rdx")
        self.asm.mov_reg_imm64("rax", 41)
        self.asm.syscall()
        dst = resolve(s.dest)
        if dst != "rax":
            self.asm.mov_reg_reg(dst, "rax")

    def _net_connect(self, s: A.NetConnect):
        self._eval(s.sock, "rdi")
        self._eval(s.addr, "rsi")
        self._eval(s.addrlen, "rdx")
        self.asm.mov_reg_imm64("rax", 42)
        self.asm.syscall()

    def _net_send(self, s: A.NetSend):
        self._eval(s.sock, "rdi")
        self._eval(s.buf, "rsi")
        self._eval(s.length, "rdx")
        self.asm.xor_reg_reg("r10", "r10")
        self.asm.mov_reg_imm64("rax", 44)  # sendto
        self.asm.syscall()

    def _net_recv(self, s: A.NetRecv):
        self._eval(s.sock, "rdi")
        self._eval(s.buf, "rsi")
        self._eval(s.length, "rdx")
        self.asm.xor_reg_reg("r10", "r10")
        self.asm.mov_reg_imm64("rax", 45)  # recvfrom
        self.asm.syscall()

    def _net_close(self, s: A.NetClose):
        self._eval(s.sock, "rdi")
        self.asm.mov_reg_imm64("rax", 3)
        self.asm.syscall()


    def _emit_fn(self, s: A.FnDef):
        """Emit function. SysV args in rdi..r9. Callee-saved regs preserved."""
        self.asm.label(f"__lbl_{s.name}")
        has_locals = bool(s.locals_)
        self.fn_locals = {}
        # Always preserve SysV callee-saved: rbx r12 r13 r14 (rbp handled by frame)
        callee = ["rbx", "r12", "r13", "r14"]
        self.asm.push_reg("rbp")
        self.asm.mov_reg_reg("rbp", "rsp")
        for r in callee:
            self.asm.push_reg(r)
        total = 0
        if has_locals:
            for name, size in s.locals_:
                size = (size + 7) & ~7
                total += size
                self.fn_locals[name] = -total - 8 * len(callee)  # below saved regs
            # layout: [rbp]=saved rbp, [rbp-8]=rbx ... [rbp-32]=r14, then locals
            # Actually after 4 pushes, rsp is rbp-32. Locals below that.
            # Offsets from rbp: first push rbx at [rbp-8], r12 [rbp-16], r13 [rbp-24], r14 [rbp-32]
            # locals start at rbp-32-size
            self.fn_locals = {}
            total = 0
            for name, size in s.locals_:
                size = (size + 7) & ~7
                total += size
                self.fn_locals[name] = -(32 + total)
            total = (total + 15) & ~15
            if total:
                self.asm.sub_reg_imm("rsp", total)
        else:
            # still keep callee space; rsp already adjusted by pushes
            pass
        self.in_fn = True
        sysv = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
        self.fn_args = {}
        for i, aname in enumerate(s.args):
            if i < len(sysv):
                self.fn_args[aname] = sysv[i]
        for stmt in s.body:
            self._emit(stmt)
        self.in_fn = False
        self.fn_locals = {}
        self.fn_args = {}
        # epilogue if fall-through
        self._fn_epilogue(callee)

    def _fn_epilogue(self, callee=None):
        callee = callee or ["rbx", "r12", "r13", "r14"]
        # leave restores rsp from rbp and pops rbp — but we need to pop callee first
        # Correct: mov rsp, rbp; sub rsp, 32; pop r14..rbx; pop rbp; ret
        # Simpler: lea rsp, [rbp-32]; pop r14; pop r13; pop r12; pop rbx; pop rbp; ret
        self.asm.mov_reg_reg("rsp", "rbp")
        self.asm.sub_reg_imm("rsp", 32)
        for r in reversed(callee):
            self.asm.pop_reg(r)
        self.asm.pop_reg("rbp")
        self.asm.ret()




    def _cell_protect(self, s: A.CellProtect):
        for r in ("r12", "r13", "r14"):
            self.asm.push_reg(r)
        self._eval(s.ptr, "r12")
        self._eval(s.size, "r13")
        self._eval(s.prot, "r14")
        self.asm.mov_reg_reg("rdi", "r12")
        self.asm.mov_reg_reg("rsi", "r13")
        self.asm.mov_reg_reg("rdx", "r14")
        self.asm.mov_reg_imm64("rax", 10)
        self.asm.syscall()
        self.asm.pop_reg("r14")
        self.asm.pop_reg("r13")
        self.asm.pop_reg("r12")

    def _sig_action(self, s: A.SigAction):
        # Build minimal struct sigaction on stack: handler, flags, restorer, mask
        # Linux x86-64: sa_handler, sa_flags, sa_restorer, sa_mask (8+8+8+8=32 for basic)
        self._eval(s.signo, "r12")
        # handler address
        if isinstance(s.handler, str) and s.handler and not s.handler.lstrip('-').isdigit():
            self.asm.lea_reg_label("r13", f"__lbl_{s.handler}")
        else:
            try:
                hv = int(s.handler, 0)
            except Exception:
                hv = 0
            self.asm.mov_reg_imm64("r13", hv)
        # stack buffer 32 bytes
        self.asm.sub_reg_imm("rsp", 32)
        self.asm.mov_mem_reg("rsp", 0, "r13")  # sa_handler
        self.asm.xor_reg_reg("rax", "rax")
        self.asm.mov_mem_reg("rsp", 8, "rax")   # flags
        self.asm.mov_mem_reg("rsp", 16, "rax")  # restorer
        self.asm.mov_mem_reg("rsp", 24, "rax")  # mask low
        self.asm.mov_reg_reg("rdi", "r12")
        self.asm.mov_reg_reg("rsi", "rsp")
        self.asm.xor_reg_reg("rdx", "rdx")  # oldact NULL
        self.asm.mov_reg_imm64("r10", 8)    # sigsetsize
        self.asm.mov_reg_imm64("rax", 13)   # rt_sigaction
        self.asm.syscall()
        self.asm.add_reg_imm("rsp", 32)



    def _kbd_poll(self, s: A.ChipKbdPoll):
        """Scancode in dest if pending, else 0."""
        dest = resolve(s.dest)
        self.asm.push_reg("rdx")
        self.asm.mov_reg_imm64("rdx", 0x64)
        self.asm.in_al_dx()
        self.asm.and_reg_imm("rax", 1)
        self.asm.test_reg_reg("rax", "rax")
        ok = self.new_label("kbdok")
        done = self.new_label("kbdd")
        self.asm.jcc("neq", ok)
        self.asm.xor_reg_reg(dest, dest)
        self.asm.jmp(done)
        self.asm.label(ok)
        self.asm.mov_reg_imm64("rdx", 0x60)
        self.asm.in_al_dx()
        if dest != "rax":
            self.asm.mov_reg_reg(dest, "rax")
        self.asm.label(done)
        self.asm.pop_reg("rdx")


    def _kernel_heap_init(self, s: A.KernelHeapInit):
        name = "__kheap"
        ptr = "__kheap_ptr"
        if name not in self.data_layout:
            self.data_layout[name] = len(self.data_bytes)
            self.data_bytes += b"\x00" * s.size
        if ptr not in self.data_layout:
            self.data_layout[ptr] = len(self.data_bytes)
            self.data_bytes += b"\x00" * 8
        # ptr = &heap[0]
        self.asm.lea_reg_label(SCRATCH, f"__data_{name}")
        self.asm.lea_reg_label("r12", f"__data_{ptr}")
        self.asm.mov_mem_reg("r12", 0, SCRATCH)

    def _kernel_heap_alloc(self, s: A.KernelHeapAlloc):
        dest = resolve(s.dest)
        self.asm.push_reg("r12")
        self.asm.lea_reg_label("r12", "__data___kheap_ptr")
        self.asm.mov_reg_mem(SCRATCH, "r12", 0)  # current
        self.asm.mov_reg_reg(dest, SCRATCH)  # return old
        self._eval(s.size, "r11")
        self.asm.add_reg_reg(SCRATCH, "r11")
        self.asm.mov_mem_reg("r12", 0, SCRATCH)
        self.asm.pop_reg("r12")

    def _kernel_ctx_save(self, s: A.KernelCtxSave):
        base = resolve(s.dest)
        # Save all GPRs at [base+i*8]; use stack to keep base
        self.asm.push_reg(base)
        self.asm.mov_reg_reg(SCRATCH, base)
        regs = ["rax","rbx","rcx","rdx","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15","rbp","rsp"]
        for i, r in enumerate(regs):
            if r == "rsp":
                # store original rsp from stack top-ish: use lea after push already changed rsp
                self.asm.mov_reg_mem("r11", "rsp", 0)  # saved base was pushed — wrong
                # skip rsp or store current
                self.asm.mov_mem_reg(SCRATCH, i * 8, "rsp")
            else:
                self.asm.mov_mem_reg(SCRATCH, i * 8, r)
        self.asm.pop_reg(base)

    def _kernel_ctx_load(self, s: A.KernelCtxLoad):
        base = resolve(s.src)
        self.asm.mov_reg_reg(SCRATCH, base)
        # load all except rsp/rbp last careful — load general first
        order = ["rax","rbx","rcx","rdx","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"]
        for i, r in enumerate(order):
            self.asm.mov_reg_mem(r, SCRATCH, i * 8)
        # rbp at 14, rsp at 15 — optional
        self.asm.mov_reg_mem("rbp", SCRATCH, 14 * 8)

    def _kernel_idt_install(self, s: A.KernelIdtInstall):
        """Runtime: fill 256 gates to __isr_default, lidt."""
        # Ensure handler exists once
        if not getattr(self, "_idt_handler_emitted", False):
            self.asm.jmp("__idt_after_handler")
            self.asm.label("__isr_default")
            self.asm.cli()
            self.asm.hlt()
            self.asm.jmp("__isr_default")
            self.asm.label("__idt_after_handler")
            self._idt_handler_emitted = True
        if "__idt" not in self.data_layout:
            self.data_layout["__idt"] = len(self.data_bytes)
            self.data_bytes += b"\x00" * (256 * 16)
        if "__idtr" not in self.data_layout:
            self.data_layout["__idtr"] = len(self.data_bytes)
            self.data_bytes += b"\x00" * 10
        # Runtime fill
        self.asm.push_reg("rax")
        self.asm.push_reg("rcx")
        self.asm.push_reg("rdx")
        self.asm.push_reg("rdi")
        self.asm.push_reg("rsi")
        self.asm.lea_reg_label("rsi", "__isr_default")  # handler addr
        self.asm.lea_reg_label("rdi", "__data___idt")
        self.asm.mov_reg_imm64("rcx", 256)
        loop = self.new_label("idtf")
        self.asm.label(loop)
        # gate: offset0 = si low, selector=0x08, type=0x8E00, offset1, offset2
        self.asm.mov_reg_reg("rax", "rsi")
        self.asm.mov_mem_reg("rdi", 0, "rax")  # writes 8 bytes — need structured
        # Simpler raw store structure via multiple movs
        # offset[15:0]
        self.asm.mov16_mem_reg("rdi", 0, "rsi")
        self.asm.mov_reg_imm64("rax", 0x08)
        self.asm.mov16_mem_reg("rdi", 2, "rax")  # selector
        self.asm.mov_reg_imm64("rax", 0x8E00)
        self.asm.mov16_mem_reg("rdi", 4, "rax")  # type attr
        self.asm.mov_reg_reg("rax", "rsi")
        self.asm.shr_reg_imm8("rax", 16)
        self.asm.mov16_mem_reg("rdi", 6, "rax")
        self.asm.mov_reg_reg("rax", "rsi")
        self.asm.shr_reg_imm8("rax", 32)
        self.asm.mov32_mem_reg("rdi", 8, "rax")
        self.asm.xor_reg_reg("rax", "rax")
        self.asm.mov32_mem_reg("rdi", 12, "rax")
        self.asm.add_reg_imm("rdi", 16)
        self.asm.sub_reg_imm("rcx", 1)
        self.asm.test_reg_reg("rcx", "rcx")
        self.asm.jcc("neq", loop)
        # idtr limit=4095, base=&idt
        self.asm.lea_reg_label("rax", "__data___idt")
        self.asm.lea_reg_label("rdi", "__data___idtr")
        self.asm.mov_reg_imm64("rcx", 256 * 16 - 1)
        self.asm.mov16_mem_reg("rdi", 0, "rcx")
        self.asm.mov_mem_reg("rdi", 2, "rax")  # 8-byte base at offset 2
        self.asm.lidt_mem("rdi", 0)
        self.asm.pop_reg("rsi")
        self.asm.pop_reg("rdi")
        self.asm.pop_reg("rdx")
        self.asm.pop_reg("rcx")
        self.asm.pop_reg("rax")


    def _pit_init(self, s: A.ChipPitInit):
        """PIT channel 0, mode 3, lo/hi divisor."""
        d = s.divisor & 0xFFFF
        self.asm.push_reg("rax")
        self.asm.push_reg("rdx")
        self.asm.mov_reg_imm64("rdx", 0x43)
        self.asm.mov_reg_imm64("rax", 0x36)  # ch0, lo/hi, mode3
        self.asm.out_dx_al()
        self.asm.mov_reg_imm64("rdx", 0x40)
        self.asm.mov_reg_imm64("rax", d & 0xFF)
        self.asm.out_dx_al()
        self.asm.mov_reg_imm64("rax", (d >> 8) & 0xFF)
        self.asm.out_dx_al()
        self.asm.pop_reg("rdx")
        self.asm.pop_reg("rax")

    def _pic_remap(self, s: A.ChipPicRemap):
        """Standard PIC remap master 0x20, slave 0x28."""
        self.asm.push_reg("rax")
        self.asm.push_reg("rdx")
        seq = [
            (0x20, 0x11), (0xA0, 0x11),
            (0x21, 0x20), (0xA1, 0x28),
            (0x21, 0x04), (0xA1, 0x02),
            (0x21, 0x01), (0xA1, 0x01),
            (0x21, 0x00), (0xA1, 0x00),
        ]
        for port, val in seq:
            self.asm.mov_reg_imm64("rdx", port)
            self.asm.mov_reg_imm64("rax", val)
            self.asm.out_dx_al()
        self.asm.pop_reg("rdx")
        self.asm.pop_reg("rax")

    def _kernel_coop_switch(self, s: A.KernelCoopSwitch):
        save = A.KernelCtxSave(dest=s.save, line=s.line, col=s.col)
        load = A.KernelCtxLoad(src=s.load, line=s.line, col=s.col)
        self._kernel_ctx_save(save)
        self._kernel_ctx_load(load)

    def _kernel_printk_str(self, s: A.KernelPrintkStr):
        self.asm.push_reg("r12")
        self._eval(s.src, "r12")
        loop = self.new_label("pks")
        done = self.new_label("pkd")
        self.asm.label(loop)
        self.asm.mov8_reg_mem(SCRATCH, "r12", 0)
        self.asm.test_reg_reg(SCRATCH, SCRATCH)
        self.asm.jcc("eq", done)
        # serial putc SCRATCH
        putc = A.ChipSerialPutc(value=A.Reg(name="r15"), line=s.line, col=s.col)
        # SCRATCH is r15 in this codebase
        from .regs import SCRATCH as SC
        self.asm.push_reg("rax")
        self.asm.push_reg("rdx")
        self.asm.mov_reg_reg("rax", SC)
        self.asm.push_reg("rax")
        wait = self.new_label("pkw")
        self.asm.label(wait)
        self.asm.mov_reg_imm64("rdx", 0x3FD)
        self.asm.in_al_dx()
        self.asm.and_reg_imm("rax", 0x20)
        self.asm.test_reg_reg("rax", "rax")
        self.asm.jcc("eq", wait)
        self.asm.pop_reg("rax")
        self.asm.mov_reg_imm64("rdx", 0x3F8)
        self.asm.out_dx_al()
        self.asm.pop_reg("rdx")
        self.asm.pop_reg("rax")
        self.asm.add_reg_imm("r12", 1)
        self.asm.jmp(loop)
        self.asm.label(done)
        self.asm.pop_reg("r12")

    def _kernel_panic(self, s: A.KernelPanic):
        self.asm.cli()
        self.asm.mov_reg_imm64("rax", ord("P"))
        self.asm.push_reg("rax")
        self.asm.mov_reg_imm64("rdx", 0x3F8)
        self.asm.pop_reg("rax")
        self.asm.out_dx_al()
        self.asm.hlt()
        panic = self.new_label("pan")
        self.asm.label(panic)
        self.asm.hlt()
        self.asm.jmp(panic)



    def _kernel_tick_install(self, s):
        if "__tick" not in self.data_layout:
            self.data_layout["__tick"] = len(self.data_bytes)
            self.data_bytes += bytes(8)
        if not getattr(self, "_irq0_emitted", False):
            self.asm.jmp("__after_irq0")
            self.asm.label("__irq0_stub")
            self.asm.push_reg("rax")
            self.asm.push_reg("rdx")
            self.asm.lea_reg_label("rax", "__data___tick")
            self.asm.mov_reg_mem("rdx", "rax", 0)
            self.asm.add_reg_imm("rdx", 1)
            self.asm.mov_mem_reg("rax", 0, "rdx")
            self.asm.mov_reg_imm64("rdx", 0x20)
            self.asm.mov_reg_imm64("rax", 0x20)
            self.asm.out_dx_al()
            self.asm.pop_reg("rdx")
            self.asm.pop_reg("rax")
            self.asm.iretq()
            self.asm.label("__after_irq0")
            self._irq0_emitted = True
        if "__idt" in self.data_layout:
            self.asm.push_reg("rax")
            self.asm.push_reg("rdi")
            self.asm.push_reg("rsi")
            self.asm.lea_reg_label("rsi", "__irq0_stub")
            self.asm.lea_reg_label("rdi", "__data___idt")
            self.asm.add_reg_imm("rdi", 32 * 16)
            self.asm.mov16_mem_reg("rdi", 0, "rsi")
            self.asm.mov_reg_imm64("rax", 0x08)
            self.asm.mov16_mem_reg("rdi", 2, "rax")
            self.asm.mov_reg_imm64("rax", 0x8E00)
            self.asm.mov16_mem_reg("rdi", 4, "rax")
            self.asm.mov_reg_reg("rax", "rsi")
            self.asm.shr_reg_imm8("rax", 16)
            self.asm.mov16_mem_reg("rdi", 6, "rax")
            self.asm.mov_reg_reg("rax", "rsi")
            self.asm.shr_reg_imm8("rax", 32)
            self.asm.mov32_mem_reg("rdi", 8, "rax")
            self.asm.xor_reg_reg("rax", "rax")
            self.asm.mov32_mem_reg("rdi", 12, "rax")
            self.asm.pop_reg("rsi")
            self.asm.pop_reg("rdi")
            self.asm.pop_reg("rax")

    def _kernel_tick_read(self, s):
        dest = resolve(s.dest)
        if "__tick" not in self.data_layout:
            self.data_layout["__tick"] = len(self.data_bytes)
            self.data_bytes += bytes(8)
        self.asm.lea_reg_label(SCRATCH, "__data___tick")
        self.asm.mov_reg_mem(dest, SCRATCH, 0)

    def _kernel_ramfs_init(self, s):
        if "__ramfs" not in self.data_layout:
            self.data_layout["__ramfs"] = len(self.data_bytes)
            self.data_bytes += bytes(256)
        self.asm.push_reg("rdi")
        self.asm.push_reg("rcx")
        self.asm.lea_reg_label("rdi", "__data___ramfs")
        self.asm.mov_reg_imm64("rcx", 256)
        self.asm.xor_reg_reg("rax", "rax")
        z = self.new_label("rfz")
        self.asm.label(z)
        self.asm.mov8_mem_reg("rdi", 0, "rax")
        self.asm.add_reg_imm("rdi", 1)
        self.asm.sub_reg_imm("rcx", 1)
        self.asm.test_reg_reg("rcx", "rcx")
        self.asm.jcc("neq", z)
        self.asm.pop_reg("rcx")
        self.asm.pop_reg("rdi")

    def _kernel_ramfs_put(self, s):
        if "__ramfs" not in self.data_layout:
            self.data_layout["__ramfs"] = len(self.data_bytes)
            self.data_bytes += bytes(256)
        self.asm.push_reg("r12")
        self.asm.push_reg("r13")
        self.asm.push_reg("r14")
        self._eval(s.name, "r12")
        self._eval(s.data, "r13")
        self._eval(s.length, "r14")
        self.asm.lea_reg_label(SCRATCH, "__data___ramfs")
        self.asm.mov_reg_imm64("rcx", 8)
        fs = self.new_label("rfs")
        found = self.new_label("rff")
        done = self.new_label("rfd")
        self.asm.label(fs)
        self.asm.mov8_reg_mem("rax", SCRATCH, 0)
        self.asm.test_reg_reg("rax", "rax")
        self.asm.jcc("eq", found)
        self.asm.add_reg_imm(SCRATCH, 32)
        self.asm.sub_reg_imm("rcx", 1)
        self.asm.test_reg_reg("rcx", "rcx")
        self.asm.jcc("neq", fs)
        self.asm.jmp(done)
        self.asm.label(found)
        self.asm.mov_reg_reg("rdi", SCRATCH)
        self.asm.mov_reg_reg("rsi", "r12")
        self.asm.mov_reg_imm64("rcx", 15)
        cn = self.new_label("rfc")
        self.asm.label(cn)
        self.asm.mov8_reg_mem("rax", "rsi", 0)
        self.asm.mov8_mem_reg("rdi", 0, "rax")
        self.asm.test_reg_reg("rax", "rax")
        self.asm.jcc("eq", done)
        self.asm.add_reg_imm("rsi", 1)
        self.asm.add_reg_imm("rdi", 1)
        self.asm.sub_reg_imm("rcx", 1)
        self.asm.test_reg_reg("rcx", "rcx")
        self.asm.jcc("neq", cn)
        self.asm.xor_reg_reg("rax", "rax")
        self.asm.mov8_mem_reg("rdi", 0, "rax")
        self.asm.label(done)
        self.asm.mov_mem_reg(SCRATCH, 16, "r13")
        self.asm.mov_mem_reg(SCRATCH, 24, "r14")
        self.asm.pop_reg("r14")
        self.asm.pop_reg("r13")
        self.asm.pop_reg("r12")

    def _kernel_ramfs_get(self, s):
        dest = resolve(s.dest)
        if "__ramfs" not in self.data_layout:
            self.data_layout["__ramfs"] = len(self.data_bytes)
            self.data_bytes += bytes(256)
        self.asm.push_reg("r12")
        self.asm.push_reg("r13")
        self.asm.push_reg("r14")
        self._eval(s.name, "r12")
        self.asm.lea_reg_label("r13", "__data___ramfs")
        self.asm.mov_reg_imm64("rcx", 8)
        loop = self.new_label("rfgl")
        fail = self.new_label("rfgf")
        ok = self.new_label("rfgok")
        done = self.new_label("rfgd")
        self.asm.label(loop)
        self.asm.mov_reg_reg("rsi", "r13")
        self.asm.mov_reg_reg("rdi", "r12")
        self.asm.mov_reg_imm64("r14", 16)
        cmpl = self.new_label("rfgc")
        self.asm.label(cmpl)
        self.asm.mov8_reg_mem("rax", "rsi", 0)
        self.asm.mov8_reg_mem("rdx", "rdi", 0)
        self.asm.cmp_reg_reg("rax", "rdx")
        ne = self.new_label("rfgne")
        self.asm.jcc("neq", ne)
        self.asm.test_reg_reg("rax", "rax")
        self.asm.jcc("eq", ok)
        self.asm.add_reg_imm("rsi", 1)
        self.asm.add_reg_imm("rdi", 1)
        self.asm.sub_reg_imm("r14", 1)
        self.asm.test_reg_reg("r14", "r14")
        self.asm.jcc("neq", cmpl)
        self.asm.jmp(ok)
        self.asm.label(ne)
        self.asm.add_reg_imm("r13", 32)
        self.asm.sub_reg_imm("rcx", 1)
        self.asm.test_reg_reg("rcx", "rcx")
        self.asm.jcc("neq", loop)
        self.asm.jmp(fail)
        self.asm.label(ok)
        self.asm.mov_reg_mem(dest, "r13", 16)
        self.asm.jmp(done)
        self.asm.label(fail)
        self.asm.xor_reg_reg(dest, dest)
        self.asm.label(done)
        self.asm.pop_reg("r14")
        self.asm.pop_reg("r13")
        self.asm.pop_reg("r12")

    def _kernel_net_init(self, s):
        if "__net" not in self.data_layout:
            self.data_layout["__net"] = len(self.data_bytes)
            self.data_bytes += bytes([1]) + bytes(7)

    def _kernel_net_poll(self, s):
        dest = resolve(s.dest)
        self.asm.xor_reg_reg(dest, dest)

    def _kernel_cs_ring(self, s):
        dest = resolve(s.dest)
        self.asm.raw_bytes(bytes([0x66, 0x8C, 0xC8]))
        self.asm.and_reg_imm("rax", 3)
        if dest != "rax":
            self.asm.mov_reg_reg(dest, "rax")


    def _kernel_enter_user(self, s):
        """Build iretq frame: SS=0x23, RSP=stack, RFLAGS=0x202, CS=0x1B, RIP=entry."""
        self.asm.push_reg("rax")
        self._eval(s.stack, "rax")
        self.asm.mov_reg_reg("rsp", "rax")
        # push SS, RSP, RFLAGS, CS, RIP (iretq order reverse)
        self.asm.mov_reg_imm64("rax", 0x23)
        self.asm.push_reg("rax")  # SS
        self._eval(s.stack, "rax")
        self.asm.push_reg("rax")  # RSP
        self.asm.mov_reg_imm64("rax", 0x202)
        self.asm.push_reg("rax")  # RFLAGS
        self.asm.mov_reg_imm64("rax", 0x1B)
        self.asm.push_reg("rax")  # CS
        self._eval(s.entry, "rax")
        self.asm.push_reg("rax")  # RIP
        self.asm.iretq()

    def _kernel_pf_install(self, s):
        if not getattr(self, "_pf_emitted", False):
            self.asm.jmp("__after_pf")
            self.asm.label("__pf_stub")
            self.asm.cli()
            self.asm.hlt()
            self.asm.jmp("__pf_stub")
            self.asm.label("__after_pf")
            self._pf_emitted = True
        if "__idt" in self.data_layout:
            self.asm.push_reg("rax")
            self.asm.push_reg("rdi")
            self.asm.push_reg("rsi")
            self.asm.lea_reg_label("rsi", "__pf_stub")
            self.asm.lea_reg_label("rdi", "__data___idt")
            self.asm.add_reg_imm("rdi", 14 * 16)
            self.asm.mov16_mem_reg("rdi", 0, "rsi")
            self.asm.mov_reg_imm64("rax", 0x08)
            self.asm.mov16_mem_reg("rdi", 2, "rax")
            self.asm.mov_reg_imm64("rax", 0x8E00)
            self.asm.mov16_mem_reg("rdi", 4, "rax")
            self.asm.mov_reg_reg("rax", "rsi")
            self.asm.shr_reg_imm8("rax", 16)
            self.asm.mov16_mem_reg("rdi", 6, "rax")
            self.asm.mov_reg_reg("rax", "rsi")
            self.asm.shr_reg_imm8("rax", 32)
            self.asm.mov32_mem_reg("rdi", 8, "rax")
            self.asm.xor_reg_reg("rax", "rax")
            self.asm.mov32_mem_reg("rdi", 12, "rax")
            self.asm.pop_reg("rsi")
            self.asm.pop_reg("rdi")
            self.asm.pop_reg("rax")

    def _kernel_net_allow(self, s):
        if "__net_allow" not in self.data_layout:
            self.data_layout["__net_allow"] = len(self.data_bytes)
            self.data_bytes += bytes(8)
        bit = 1 << (s.port & 63)
        self.asm.push_reg("rax")
        self.asm.push_reg("rcx")
        self.asm.lea_reg_label("rax", "__data___net_allow")
        self.asm.mov_reg_mem("rcx", "rax", 0)
        self.asm.mov_reg_imm64("rdx", bit)
        self.asm.or_reg_reg("rcx", "rdx")
        self.asm.mov_mem_reg("rax", 0, "rcx")
        self.asm.pop_reg("rcx")
        self.asm.pop_reg("rax")

    def _kernel_net_check(self, s):
        dest = resolve(s.dest)
        if "__net_allow" not in self.data_layout:
            self.data_layout["__net_allow"] = len(self.data_bytes)
            self.data_bytes += bytes(8)
        self.asm.push_reg("rcx")
        self.asm.push_reg("rdx")
        self.asm.push_reg("rsi")
        self._eval(s.port, "rcx")
        self.asm.and_reg_imm("rcx", 63)
        self.asm.lea_reg_label("rsi", "__data___net_allow")
        self.asm.mov_reg_mem("rdx", "rsi", 0)
        bit = None
        # variable shift: rdx & (1<<cl)
        self.asm.mov_reg_imm64("rsi", 1)
        self.asm.shl_reg_cl("rsi")
        self.asm.and_reg_reg("rdx", "rsi")
        self.asm.test_reg_reg("rdx", "rdx")
        nz = self.new_label("nck")
        z = self.new_label("nckz")
        self.asm.jcc("neq", nz)
        self.asm.xor_reg_reg(dest, dest)
        self.asm.jmp(z)
        self.asm.label(nz)
        self.asm.mov_reg_imm64(dest, 1)
        self.asm.label(z)
        self.asm.pop_reg("rsi")
        self.asm.pop_reg("rdx")
        self.asm.pop_reg("rcx")

    def _kernel_preempt_arm(self, s):
        if "__preempt_req" not in self.data_layout:
            self.data_layout["__preempt_req"] = len(self.data_bytes)
            self.data_bytes += bytes(8)
        self.asm.push_reg("rax")
        self.asm.lea_reg_label("rax", "__data___preempt_req")
        self.asm.mov_mem_reg("rax", 0, resolve(s.ctx))
        self.asm.pop_reg("rax")


    def _kernel_syscall_init(self, s):
        """Enable SCE; STAR kernel 0x08 / user 0x1B; LSTAR=__syscall_entry; SFMASK."""
        if not getattr(self, "_sysentry_emitted", False):
            self.asm.jmp("__after_sysentry")
            self.asm.label("__syscall_entry")
            # Minimal: return to user via sysret (rcx/r11 already user state from syscall)
            self.asm.sysret()
            self.asm.label("__after_sysentry")
            self._sysentry_emitted = True
        self.asm.push_reg("rax")
        self.asm.push_reg("rcx")
        self.asm.push_reg("rdx")
        # EFER |= SCE (bit 0)
        self.asm.mov_reg_imm64("rcx", 0xC0000080)
        self.asm.rdmsr()
        self.asm.or_reg_imm("rax", 1)
        self.asm.wrmsr()
        # STAR: [63:48]=user_cs 0x1B, [47:32]=kernel_cs 0x08
        self.asm.mov_reg_imm64("rcx", 0xC0000081)
        self.asm.mov_reg_imm64("rax", 0)
        self.asm.mov_reg_imm64("rdx", (0x1B << 16) | 0x08)  # high 32 of STAR in edx
        # Actually STAR is one 64-bit in edx:eax — edx=high, eax=low
        # STAR = (user_cs << 48) | (kernel_cs << 32) | ...
        # edx = (user_cs << 16) | kernel_cs = 0x001B0008
        self.asm.mov_reg_imm64("rdx", 0x001B0008)
        self.asm.xor_reg_reg("rax", "rax")
        self.asm.wrmsr()
        # LSTAR = &__syscall_entry
        self.asm.mov_reg_imm64("rcx", 0xC0000082)
        self.asm.lea_reg_label("rax", "__syscall_entry")
        self.asm.mov_reg_reg("rdx", "rax")
        self.asm.shr_reg_imm8("rdx", 32)
        self.asm.wrmsr()
        # SFMASK clear IF and DF etc
        self.asm.mov_reg_imm64("rcx", 0xC0000084)
        self.asm.mov_reg_imm64("rax", 0x200)
        self.asm.xor_reg_reg("rdx", "rdx")
        self.asm.wrmsr()
        self.asm.pop_reg("rdx")
        self.asm.pop_reg("rcx")
        self.asm.pop_reg("rax")

    def _kernel_nic_bar(self, s):
        if "__nic_bar" not in self.data_layout:
            self.data_layout["__nic_bar"] = len(self.data_bytes)
            self.data_bytes += bytes(8)
        self.asm.push_reg("rax")
        self._eval(s.addr, "rax")
        self.asm.lea_reg_label(SCRATCH, "__data___nic_bar")
        self.asm.mov_mem_reg(SCRATCH, 0, "rax")
        self.asm.pop_reg("rax")

    def _kernel_nic_read(self, s):
        dest = resolve(s.dest)
        if "__nic_bar" not in self.data_layout:
            self.data_layout["__nic_bar"] = len(self.data_bytes)
            self.data_bytes += bytes(8)
        self.asm.push_reg("rdx")
        self.asm.push_reg("rsi")
        self.asm.lea_reg_label("rsi", "__data___nic_bar")
        self.asm.mov_reg_mem("rsi", "rsi", 0)
        self._eval(s.offset, "rdx")
        self.asm.add_reg_reg("rsi", "rdx")
        self.asm.mov32_reg_mem(dest, "rsi", 0)
        self.asm.pop_reg("rsi")
        self.asm.pop_reg("rdx")


    def _kernel_nic_write(self, s):
        if "__nic_bar" not in self.data_layout:
            self.data_layout["__nic_bar"] = len(self.data_bytes)
            self.data_bytes += bytes(8)
        self.asm.push_reg("rax")
        self.asm.push_reg("rdx")
        self.asm.push_reg("rcx")
        self.asm.lea_reg_label("rax", "__data___nic_bar")
        self.asm.mov_reg_mem("rax", "rax", 0)
        self._eval(s.offset, "rdx")
        self.asm.add_reg_reg("rax", "rdx")
        self._eval(s.value, "rcx")
        self.asm.mov32_mem_reg("rax", 0, "rcx")
        self.asm.pop_reg("rcx")
        self.asm.pop_reg("rdx")
        self.asm.pop_reg("rax")

    def _kernel_irq_full_save_on(self, s):
        """Allocate 128-byte __irq_gprs; rebuild IRQ0 to save/restore all GPRs."""
        if "__irq_gprs" not in self.data_layout:
            self.data_layout["__irq_gprs"] = len(self.data_bytes)
            self.data_bytes += bytes(128)
        if "__tick" not in self.data_layout:
            self.data_layout["__tick"] = len(self.data_bytes)
            self.data_bytes += bytes(8)
        # Emit new full-save IRQ0 (label unique)
        if not getattr(self, "_irq0_full_emitted", False):
            self.asm.jmp("__after_irq0_full")
            self.asm.label("__irq0_full")
            # save rax first via push then move to buffer using rsp tricks — use r15 as base after push
            self.asm.push_reg("r15")
            self.asm.lea_reg_label("r15", "__data___irq_gprs")
            self.asm.mov_mem_reg("r15", 0, "rax")
            self.asm.mov_mem_reg("r15", 8, "rbx")
            self.asm.mov_mem_reg("r15", 16, "rcx")
            self.asm.mov_mem_reg("r15", 24, "rdx")
            self.asm.mov_mem_reg("r15", 32, "rsi")
            self.asm.mov_mem_reg("r15", 40, "rdi")
            self.asm.mov_mem_reg("r15", 48, "r8")
            self.asm.mov_mem_reg("r15", 56, "r9")
            self.asm.mov_mem_reg("r15", 64, "r10")
            self.asm.mov_mem_reg("r15", 72, "r11")
            self.asm.mov_mem_reg("r15", 80, "r12")
            self.asm.mov_mem_reg("r15", 88, "r13")
            self.asm.mov_mem_reg("r15", 96, "r14")
            # r15 saved on stack
            self.asm.mov_reg_mem("rax", "rsp", 0)
            self.asm.mov_mem_reg("r15", 104, "rax")
            # tick++
            self.asm.lea_reg_label("rax", "__data___tick")
            self.asm.mov_reg_mem("rdx", "rax", 0)
            self.asm.add_reg_imm("rdx", 1)
            self.asm.mov_mem_reg("rax", 0, "rdx")
            # EOI
            self.asm.mov_reg_imm64("rdx", 0x20)
            self.asm.mov_reg_imm64("rax", 0x20)
            self.asm.out_dx_al()
            # restore
            self.asm.lea_reg_label("r15", "__data___irq_gprs")
            self.asm.mov_reg_mem("rax", "r15", 0)
            self.asm.mov_reg_mem("rbx", "r15", 8)
            self.asm.mov_reg_mem("rcx", "r15", 16)
            self.asm.mov_reg_mem("rdx", "r15", 24)
            self.asm.mov_reg_mem("rsi", "r15", 32)
            self.asm.mov_reg_mem("rdi", "r15", 40)
            self.asm.mov_reg_mem("r8", "r15", 48)
            self.asm.mov_reg_mem("r9", "r15", 56)
            self.asm.mov_reg_mem("r10", "r15", 64)
            self.asm.mov_reg_mem("r11", "r15", 72)
            self.asm.mov_reg_mem("r12", "r15", 80)
            self.asm.mov_reg_mem("r13", "r15", 88)
            self.asm.mov_reg_mem("r14", "r15", 96)
            self.asm.pop_reg("r15")
            self.asm.iretq()
            self.asm.label("__after_irq0_full")
            self._irq0_full_emitted = True
        # Patch IDT[32] to __irq0_full if IDT exists
        if "__idt" in self.data_layout:
            self.asm.push_reg("rax")
            self.asm.push_reg("rdi")
            self.asm.push_reg("rsi")
            self.asm.lea_reg_label("rsi", "__irq0_full")
            self.asm.lea_reg_label("rdi", "__data___idt")
            self.asm.add_reg_imm("rdi", 32 * 16)
            self.asm.mov16_mem_reg("rdi", 0, "rsi")
            self.asm.mov_reg_imm64("rax", 0x08)
            self.asm.mov16_mem_reg("rdi", 2, "rax")
            self.asm.mov_reg_imm64("rax", 0x8E00)
            self.asm.mov16_mem_reg("rdi", 4, "rax")
            self.asm.mov_reg_reg("rax", "rsi")
            self.asm.shr_reg_imm8("rax", 16)
            self.asm.mov16_mem_reg("rdi", 6, "rax")
            self.asm.mov_reg_reg("rax", "rsi")
            self.asm.shr_reg_imm8("rax", 32)
            self.asm.mov32_mem_reg("rdi", 8, "rax")
            self.asm.xor_reg_reg("rax", "rax")
            self.asm.mov32_mem_reg("rdi", 12, "rax")
            self.asm.pop_reg("rsi")
            self.asm.pop_reg("rdi")
            self.asm.pop_reg("rax")


    def _kernel_syscall_table_init(self, s):
        # 64 * 8 pointers
        if "__systab" not in self.data_layout:
            self.data_layout["__systab"] = len(self.data_bytes)
            self.data_bytes += bytes(64 * 8)
        if not getattr(self, "_nosys_emitted", False):
            self.asm.jmp("__after_nosys")
            self.asm.label("__nosys")
            self.asm.mov_reg_imm64("rax", 0xFFFFFFFFFFFFFFFF)  # -1 ENOSYS
            self.asm.sysret()
            self.asm.label("__after_nosys")
            self._nosys_emitted = True
        # fill all slots with __nosys
        self.asm.push_reg("rax")
        self.asm.push_reg("rcx")
        self.asm.push_reg("rdi")
        self.asm.lea_reg_label("rax", "__nosys")
        self.asm.lea_reg_label("rdi", "__data___systab")
        self.asm.mov_reg_imm64("rcx", 64)
        loop = self.new_label("sti")
        self.asm.label(loop)
        self.asm.mov_mem_reg("rdi", 0, "rax")
        self.asm.add_reg_imm("rdi", 8)
        self.asm.sub_reg_imm("rcx", 1)
        self.asm.test_reg_reg("rcx", "rcx")
        self.asm.jcc("neq", loop)
        self.asm.pop_reg("rdi")
        self.asm.pop_reg("rcx")
        self.asm.pop_reg("rax")
        # Replace __syscall_entry to dispatch
        if not getattr(self, "_sysdispatch_emitted", False):
            self.asm.jmp("__after_sysdispatch")
            self.asm.label("__syscall_dispatch")
            # rax = nr; clamp 0..63; call [tab+rax*8]
            self.asm.push_reg("rbx")
            self.asm.mov_reg_reg("rbx", "rax")
            self.asm.and_reg_imm("rbx", 63)
            self.asm.lea_reg_label("rax", "__data___systab")
            self.asm.shl_reg_imm8("rbx", 3)
            self.asm.add_reg_reg("rax", "rbx")
            self.asm.mov_reg_mem("rax", "rax", 0)
            self.asm.call_reg("rax")
            self.asm.pop_reg("rbx")
            self.asm.sysret()
            self.asm.label("__after_sysdispatch")
            self._sysdispatch_emitted = True
        # Point LSTAR to dispatch if syscall_init already ran — user should call table_init then syscall_init
        # Or patch: lea into LSTAR here
        self.asm.push_reg("rax")
        self.asm.push_reg("rcx")
        self.asm.push_reg("rdx")
        self.asm.mov_reg_imm64("rcx", 0xC0000082)
        self.asm.lea_reg_label("rax", "__syscall_dispatch")
        self.asm.mov_reg_reg("rdx", "rax")
        self.asm.shr_reg_imm8("rdx", 32)
        self.asm.wrmsr()
        self.asm.pop_reg("rdx")
        self.asm.pop_reg("rcx")
        self.asm.pop_reg("rax")

    def _kernel_syscall_register(self, s):
        if "__systab" not in self.data_layout:
            self.data_layout["__systab"] = len(self.data_bytes)
            self.data_bytes += bytes(64 * 8)
        self.asm.push_reg("rax")
        self.asm.push_reg("rdi")
        self.asm.lea_reg_label("rax", f"__lbl_{s.handler}")
        self.asm.lea_reg_label("rdi", "__data___systab")
        self.asm.add_reg_imm("rdi", (s.nr & 63) * 8)
        self.asm.mov_mem_reg("rdi", 0, "rax")
        self.asm.pop_reg("rdi")
        self.asm.pop_reg("rax")

    def _kernel_nmi_install(self, s):
        if not getattr(self, "_nmi_emitted", False):
            self.asm.jmp("__after_nmi")
            self.asm.label("__nmi_stub")
            self.asm.cli()
            self.asm.hlt()
            self.asm.jmp("__nmi_stub")
            self.asm.label("__after_nmi")
            self._nmi_emitted = True
        if "__idt" in self.data_layout:
            self.asm.push_reg("rax")
            self.asm.push_reg("rdi")
            self.asm.push_reg("rsi")
            self.asm.lea_reg_label("rsi", "__nmi_stub")
            self.asm.lea_reg_label("rdi", "__data___idt")
            self.asm.add_reg_imm("rdi", 2 * 16)
            self.asm.mov16_mem_reg("rdi", 0, "rsi")
            self.asm.mov_reg_imm64("rax", 0x08)
            self.asm.mov16_mem_reg("rdi", 2, "rax")
            self.asm.mov_reg_imm64("rax", 0x8E00)
            self.asm.mov16_mem_reg("rdi", 4, "rax")
            self.asm.mov_reg_reg("rax", "rsi")
            self.asm.shr_reg_imm8("rax", 16)
            self.asm.mov16_mem_reg("rdi", 6, "rax")
            self.asm.mov_reg_reg("rax", "rsi")
            self.asm.shr_reg_imm8("rax", 32)
            self.asm.mov32_mem_reg("rdi", 8, "rax")
            self.asm.xor_reg_reg("rax", "rax")
            self.asm.mov32_mem_reg("rdi", 12, "rax")
            self.asm.pop_reg("rsi")
            self.asm.pop_reg("rdi")
            self.asm.pop_reg("rax")

    def _kernel_dma_ring_init(self, s):
        # layout: head u32, tail u32, mask u32, pad u32, then slots*(addr u64, len u64)
        n = s.slots
        size = 16 + n * 16
        if "__dmaring" not in self.data_layout:
            self.data_layout["__dmaring"] = len(self.data_bytes)
            self.data_bytes += bytes(size)
            self.data_layout["__dmaring_slots"] = n
        self.asm.push_reg("rax")
        self.asm.push_reg("rdi")
        self.asm.lea_reg_label("rdi", "__data___dmaring")
        self.asm.xor_reg_reg("rax", "rax")
        self.asm.mov_mem_reg("rdi", 0, "rax")  # head
        self.asm.mov_mem_reg("rdi", 4, "rax")  # tail
        self.asm.mov_reg_imm64("rax", n - 1)
        self.asm.mov32_mem_reg("rdi", 8, "rax")  # mask
        self.asm.pop_reg("rdi")
        self.asm.pop_reg("rax")


    def _kernel_dma_ring_push(self, s):
        # status in reg1: 0 ok, 1 full. Temps: r8-r11
        self.asm.push_reg("r8")
        self.asm.push_reg("r9")
        self.asm.push_reg("r10")
        self.asm.push_reg("r11")
        self.asm.lea_reg_label("r8", "__data___dmaring")
        self.asm.mov32_reg_mem("r9", "r8", 0)   # head
        self.asm.mov32_reg_mem("r10", "r8", 4)  # tail
        self.asm.mov32_reg_mem("r11", "r8", 8)  # mask
        self.asm.mov_reg_reg("rax", "r9")
        self.asm.add_reg_imm("rax", 1)
        self.asm.and_reg_reg("rax", "r11")
        self.asm.cmp_reg_reg("rax", "r10")
        full = self.new_label("dmf")
        ok = self.new_label("dmo")
        self.asm.jcc("eq", full)
        self.asm.mov_reg_reg("rax", "r9")
        self.asm.shl_reg_imm8("rax", 4)
        self.asm.add_reg_imm("rax", 16)
        self.asm.add_reg_reg("rax", "r8")
        self.asm.mov_reg_reg("r10", "rax")  # slot ptr
        self._eval(s.addr, "rax")
        self.asm.mov_mem_reg("r10", 0, "rax")
        self._eval(s.length, "rax")
        self.asm.mov_mem_reg("r10", 8, "rax")
        self.asm.mov_reg_reg("rax", "r9")
        self.asm.add_reg_imm("rax", 1)
        self.asm.and_reg_reg("rax", "r11")
        self.asm.mov32_mem_reg("r8", 0, "rax")
        self.asm.xor_reg_reg(resolve("reg1"), resolve("reg1"))
        self.asm.jmp(ok)
        self.asm.label(full)
        self.asm.mov_reg_imm64(resolve("reg1"), 1)
        self.asm.label(ok)
        self.asm.pop_reg("r11")
        self.asm.pop_reg("r10")
        self.asm.pop_reg("r9")
        self.asm.pop_reg("r8")

    def _kernel_dma_ring_pop(self, s):
        da = resolve(s.dest_addr)
        dl = resolve(s.dest_len)
        self.asm.push_reg("r8")
        self.asm.push_reg("r9")
        self.asm.push_reg("r10")
        self.asm.push_reg("r11")
        self.asm.lea_reg_label("r8", "__data___dmaring")
        self.asm.mov32_reg_mem("r9", "r8", 0)   # head
        self.asm.mov32_reg_mem("r10", "r8", 4)  # tail
        self.asm.cmp_reg_reg("r9", "r10")
        empty = self.new_label("dme")
        ok = self.new_label("dmok")
        self.asm.jcc("eq", empty)
        self.asm.mov32_reg_mem("r11", "r8", 8)  # mask
        self.asm.mov_reg_reg("rax", "r10")
        self.asm.shl_reg_imm8("rax", 4)
        self.asm.add_reg_imm("rax", 16)
        self.asm.add_reg_reg("rax", "r8")
        self.asm.mov_reg_mem(da, "rax", 0)
        self.asm.mov_reg_mem(dl, "rax", 8)
        self.asm.add_reg_imm("r10", 1)
        self.asm.and_reg_reg("r10", "r11")
        self.asm.mov32_mem_reg("r8", 4, "r10")
        self.asm.xor_reg_reg(resolve("reg1"), resolve("reg1"))
        self.asm.jmp(ok)
        self.asm.label(empty)
        self.asm.mov_reg_imm64(resolve("reg1"), 1)
        self.asm.label(ok)
        self.asm.pop_reg("r11")
        self.asm.pop_reg("r10")
        self.asm.pop_reg("r9")
        self.asm.pop_reg("r8")

    def _serial_init(self):
        """COM1 (0x3F8) 115200 8N1 — uses dx/ax, saves/restores via push."""
        self.asm.push_reg("rax")
        self.asm.push_reg("rdx")
        self.asm.mov_reg_imm64("rdx", 0x3F9)
        self.asm.xor_reg_reg("rax", "rax")
        self.asm.out_dx_al()
        self.asm.mov_reg_imm64("rdx", 0x3FB)
        self.asm.mov_reg_imm64("rax", 0x80)
        self.asm.out_dx_al()
        self.asm.mov_reg_imm64("rdx", 0x3F8)
        self.asm.mov_reg_imm64("rax", 0x01)
        self.asm.out_dx_al()
        self.asm.mov_reg_imm64("rdx", 0x3F9)
        self.asm.xor_reg_reg("rax", "rax")
        self.asm.out_dx_al()
        self.asm.mov_reg_imm64("rdx", 0x3FB)
        self.asm.mov_reg_imm64("rax", 0x03)
        self.asm.out_dx_al()
        self.asm.mov_reg_imm64("rdx", 0x3FA)
        self.asm.mov_reg_imm64("rax", 0xC7)
        self.asm.out_dx_al()
        self.asm.mov_reg_imm64("rdx", 0x3FC)
        self.asm.mov_reg_imm64("rax", 0x0B)
        self.asm.out_dx_al()
        self.asm.pop_reg("rdx")
        self.asm.pop_reg("rax")

    def _serial_putc(self, s):
        """Poll LSR (0x3FD bit5) then out to 0x3F8."""
        self.asm.push_reg("rax")
        self.asm.push_reg("rdx")
        self._eval(s.value, "rax")
        self.asm.push_reg("rax")
        loop = self.new_label("ser")
        self.asm.label(loop)
        self.asm.mov_reg_imm64("rdx", 0x3FD)
        self.asm.in_al_dx()
        self.asm.and_reg_imm("rax", 0x20)
        self.asm.test_reg_reg("rax", "rax")
        self.asm.jcc("eq", loop)
        self.asm.pop_reg("rax")
        self.asm.mov_reg_imm64("rdx", 0x3F8)
        self.asm.out_dx_al()
        self.asm.pop_reg("rdx")
        self.asm.pop_reg("rax")

    def _build_baremetal_kernel(self, code_b: bytes, data_b: bytes) -> bytes:
        """Multiboot1 + long-mode trampoline + 64-bit user payload (Tier-1).

        See aclm/kernel_boot.py and docs/KERNEL_CONTRACT.md.
        """
        from .kernel_boot import build_long_mode_kernel
        # Empty body: still produce bootable image with hlt in 64-bit side
        payload = code_b if code_b else bytes([0xF4, 0xEB, 0xFE])
        return build_long_mode_kernel(payload, data_b)

