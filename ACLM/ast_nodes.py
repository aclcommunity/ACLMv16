"""ACLM AST — minimal metal IR."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional, Union, Any


@dataclass
class Node:
    line: int = 1
    col: int = 1


@dataclass
class Program(Node):
    statements: List[Node] = field(default_factory=list)


@dataclass
class Number(Node):
    value: int = 0


@dataclass
class String(Node):
    value: str = ""


@dataclass
class Reg(Node):
    name: str = ""  # virtual or physical, unresolved


@dataclass
class Ident(Node):
    name: str = ""  # data label / const name


@dataclass
class Label(Node):
    name: str = ""


@dataclass
class Goto(Node):
    label: str = ""


@dataclass
class JumpIf(Node):
    cond: str = "eq"
    label: str = ""


@dataclass
class Cmp(Node):
    left: Any = None
    right: Any = None


@dataclass
class CpuBin(Node):
    op: str = "set"  # set add sub mul div mod and or xor shl shr
    dest: str = "reg1"
    value: Any = None


@dataclass
class CpuUnary(Node):
    op: str = "inc"  # not neg inc dec
    dest: str = "reg1"


@dataclass
class DataAlloc(Node):
    name: str = ""
    size: int = 0


@dataclass
class DataConst(Node):
    name: str = ""
    value: Any = None  # Number or String


@dataclass
class MemLoad(Node):
    dest: str = "reg1"
    base: Any = None  # Reg or Ident
    offset: int = 0
    size: int = 64  # 8 16 32 64
    index: Any = None
    scale: int = 1


@dataclass
class MemStore(Node):
    base: Any = None
    offset: int = 0
    value: Any = None
    size: int = 64
    index: Any = None
    scale: int = 1


@dataclass
class SysCall(Node):
    num: Any = None  # Number or str name
    args: List[Any] = field(default_factory=list)


@dataclass
class Call(Node):
    label: str = ""
    args: List[Any] = field(default_factory=list)


@dataclass
class Ret(Node):
    pass


@dataclass
class StackPush(Node):
    value: Any = None


@dataclass
class StackPop(Node):
    dest: str = "reg1"


@dataclass
class BlastFill(Node):
    """blast:fill dest = byte, length — byte fill, dest reg preserved."""
    dest: str = "reg1"
    byte_val: Any = None
    length: Any = None


@dataclass
class BlastCopy(Node):
    """blast:copy dest = src, length — byte copy."""
    dest: str = "reg1"
    src: Any = None
    length: Any = None


@dataclass
class WireLen(Node):
    dest: str = "reg1"
    src: Any = None


@dataclass
class WireCmp(Node):
    dest: str = "reg1"
    left: Any = None
    right: Any = None


@dataclass
class WireCopy(Node):
    dest: Any = None
    src: Any = None


@dataclass
class WireEmit(Node):
    src: Any = None
    length: Any = None  # optional


@dataclass
class TrapNeg(Node):
    """Jump to label if rax (reg1) < 0 — Linux syscall error."""
    label: str = ""


@dataclass
class CellMap(Node):
    """cell:map dest = size [, prot [, flags]] — anonymous mmap."""
    dest: str = "reg1"
    size: Any = None
    prot: Any = None   # default 3 RW
    flags: Any = None  # default 0x22 PRIVATE|ANON


@dataclass
class CellFree(Node):
    """cell:free ptr, size — munmap."""
    ptr: Any = None
    size: Any = None


@dataclass
class GateCas(Node):
    """gate:cas addr = expected_reg, desired_reg — lock cmpxchg; expected updated to old."""
    addr: str = "reg1"
    expected: str = "reg2"
    desired: str = "reg3"


@dataclass
class GateSpin(Node):
    """gate:spin addr — spin until [addr]==0 then set 1."""
    addr: str = "reg1"


@dataclass
class PulseSleep(Node):
    """pulse:sleep ns — nanosleep."""
    ns: Any = None


@dataclass
class PulseNow(Node):
    """pulse:now dest — CLOCK_MONOTONIC seconds in dest (coarse)."""
    dest: str = "reg1"


@dataclass
class FlagSetcc(Node):
    """flag:setcc dest = cond — SETcc after prior cmp."""
    dest: str = "reg1"
    cond: str = "eq"


@dataclass
class ChipTicks(Node):
    """chip:ticks dest — RDTSC low 32 in dest (or full via edx:eax policy: low in dest)."""
    dest: str = "reg1"


@dataclass
class ChipId(Node):
    """chip:id leaf → writes eax,ebx,ecx,edx into four dest regs."""
    leaf: Any = None
    dest_a: str = "reg1"
    dest_b: str = "reg2"
    dest_c: str = "reg3"
    dest_d: str = "reg4"


@dataclass
class ChipCli(Node):
    pass


@dataclass
class ChipSti(Node):
    pass


@dataclass
class ChipHalt(Node):
    pass


@dataclass
class GateFence(Node):
    """gate:fence [kind] — mfence default; lfence/sfence optional."""
    kind: str = "mfence"


@dataclass
class PortOut(Node):
    """port:out port = value — out dx, al (port in dx, value in al)."""
    port: Any = None
    value: Any = None


@dataclass
class PortIn(Node):
    """port:in dest = port"""
    dest: str = "reg1"
    port: Any = None


@dataclass
class VecLoad(Node):
    xmm: str = "xmm0"
    base: Any = None
    offset: int = 0


@dataclass
class VecStore(Node):
    base: Any = None
    offset: int = 0
    xmm: str = "xmm0"


@dataclass
class VecBin(Node):
    op: str = "addps"  # addps subps mulps divps
    dst: str = "xmm0"
    src: str = "xmm1"


@dataclass
class CpuLea(Node):
    """cpu:lea dest = [base + disp] or [base + index * scale + disp]"""
    dest: str = "reg1"
    base: Any = None
    index: Any = None
    scale: int = 1
    offset: int = 0


@dataclass
class SysRaw(Node):
    """sys:raw num a b c d e f — explicit syscall number + up to 6 args."""
    num: Any = None
    args: list = None

    def __post_init__(self):
        if self.args is None:
            self.args = []


@dataclass
class RawBytes(Node):
    """raw: hex bytes inline — maximum freedom escape hatch."""
    hex_parts: list = None  # list of int bytes

    def __post_init__(self):
        if self.hex_parts is None:
            self.hex_parts = []


@dataclass
class CpuTest(Node):
    """cpu:test a, b — test r/r or r/imm (flags only)"""
    left: Any = None
    right: Any = None


@dataclass
class CpuCmov(Node):
    """cpu:cmov dest = src, cond — cmovcc"""
    dest: str = "reg1"
    src: Any = None
    cond: str = "eq"


@dataclass
class Include(Node):
    """include: \"file.aclm\" — compile-time splice"""
    path: str = ""


@dataclass
class ThreadSpawn(Node):
    """thread:spawn dest = ~label"""
    dest: str = "reg1"
    label: str = ""


@dataclass
class ThreadJoin(Node):
    """thread:join tid — best-effort wait"""
    tid: Any = None


@dataclass
class ThreadExit(Node):
    code: Any = None


@dataclass
class VecVBin(Node):
    """vec:vaddps ymm0 = ymm1 (AVX)"""
    op: str = "vaddps"
    dst: str = "ymm0"
    src: str = "ymm1"
    imm: int = 0


@dataclass
class VecVLoad(Node):
    ymm: str = "ymm0"
    base: Any = None
    offset: int = 0


@dataclass
class VecVStore(Node):
    base: Any = None
    offset: int = 0
    ymm: str = "ymm0"


@dataclass
class ErrStatus(Node):
    """err:status dest — copy rax (syscall result) to dest"""
    dest: str = "reg1"


@dataclass
class CpuXchg(Node):
    a: str = "reg1"
    b: str = "reg2"


@dataclass
class CpuXadd(Node):
    dest: str = "reg1"
    src: str = "reg2"


@dataclass
class CpuBitScan(Node):
    op: str = "bsf"  # bsf bsr
    dest: str = "reg1"
    src: Any = None


@dataclass
class CpuBt(Node):
    base: str = "reg1"
    offset: Any = None


@dataclass
class BlastRepFill(Node):
    dest: str = "reg1"
    byte_val: Any = None
    length: Any = None


@dataclass
class BlastRepCopy(Node):
    dest: str = "reg1"
    src: Any = None
    length: Any = None


@dataclass
class NetSocket(Node):
    dest: str = "reg1"
    domain: Any = None
    type_: Any = None
    protocol: Any = None


@dataclass
class NetConnect(Node):
    sock: Any = None
    addr: Any = None
    addrlen: Any = None


@dataclass
class NetSend(Node):
    sock: Any = None
    buf: Any = None
    length: Any = None


@dataclass
class NetRecv(Node):
    sock: Any = None
    buf: Any = None
    length: Any = None


@dataclass
class NetClose(Node):
    sock: Any = None


@dataclass
class TargetBaremetal(Node):
    """Directive: emit Multiboot ELF32 artifact."""
    pass


# ---- Stage-6: Structs, Functions, Expressions ----

@dataclass
class StructDef(Node):
    """struct: Name ... end:struct"""
    name: str = ""
    fields: List[tuple] = field(default_factory=list)  # list of (field_name, size_bytes)


@dataclass
class StructFieldRef(Node):
    """Point.x  →  offset of field x in struct Point"""
    struct: str = ""
    field: str = ""


@dataclass
class FnDef(Node):
    """fn: name arg1 arg2 ... body ... end:fn"""
    name: str = ""
    args: List[str] = field(default_factory=list)  # virtual reg names or arg names
    body: List[Node] = field(default_factory=list)
    locals_: List[tuple] = field(default_factory=list)  # (name, size)


@dataclass
class LocalDecl(Node):
    """local: name = size"""
    name: str = ""
    size: int = 8


@dataclass
class RetVal(Node):
    """ret value  (optional value)"""
    value: Any = None


@dataclass
class BinExpr(Node):
    """Simple binary expression: left op right"""
    op: str = "+"  # + - * & | ^
    left: Any = None
    right: Any = None


@dataclass
class CpuMovExt(Node):
    """cpu:movzx / cpu:movsx dest = src  (width from suffix or size field)"""
    op: str = "movzx"  # movzx | movsx
    dest: str = "reg1"
    src: Any = None
    size: int = 8  # 8 or 16 source width


@dataclass
class DataBytes(Node):
    """data:bytes name = 0xDE 0xAD ..."""
    name: str = ""
    values: list = None  # list of int

    def __post_init__(self):
        if self.values is None:
            self.values = []


@dataclass
class FlagsClear(Node):
    """flags:clear — cld (DF=0); minimal portable flag hygiene for string ops"""
    pass


@dataclass
class FlagsSetDF(Node):
    """flags:set DF — std"""
    pass


@dataclass
class MetalRegs(Node):
    """metal:regs — listing annotation only (no code)"""
    pass


@dataclass
class AssertBytes(Node):
    """assert:bytes label <= N  — teach/check code size from label to here or named region"""
    name: str = ""
    limit: int = 0
    op: str = "le"  # le | eq


@dataclass
class AssertSize(Node):
    """assert:size code|data <= N"""
    what: str = "code"  # code | data
    limit: int = 0


@dataclass
class MetalDeterministic(Node):
    """metal:deterministic — prefer stable encodings"""
    pass


@dataclass
class CpuLeaRip(Node):
    """cpu:lea dest = [rip + label]"""
    dest: str = "reg1"
    label: str = ""


@dataclass
class CpuLeaAbs(Node):
    """cpu:lea dest = [abs imm] — movabs of absolute address"""
    dest: str = "reg1"
    addr: int = 0


@dataclass
class DataAlign(Node):
    """data:align N — pad data section to alignment"""
    align: int = 8


@dataclass
class SectionAt(Node):
    """section:text at:ADDR — recorded for listing/baremetal hints (ELF still relocates)"""
    name: str = "text"
    addr: int = 0


@dataclass
class CpuShld(Node):
    dest: str = "reg1"
    src: str = "reg2"


@dataclass
class CpuShrd(Node):
    dest: str = "reg1"
    src: str = "reg2"


@dataclass
class CpuImulImm(Node):
    dest: str = "reg1"
    imm: int = 0


@dataclass
class CpuAndn(Node):
    dest: str = "reg1"
    src1: str = "reg2"
    src2: str = "reg3"


@dataclass
class CpuBzhi(Node):
    dest: str = "reg1"
    src: str = "reg2"
    ctrl: str = "reg3"


@dataclass
class CpuCmpxchg16b(Node):
    base: Any = None
    offset: int = 0


@dataclass
class CpuCmovMem(Node):
    dest: str = "reg1"
    base: Any = None
    offset: int = 0
    cond: str = "eq"


@dataclass
class PrefixedOp(Node):
    """lock: or rep: before a following metal op — stored as marker."""
    prefix: str = "lock"


@dataclass
class CellProtect(Node):
    """cell:protect ptr, size, prot — mprotect."""
    ptr: Any = None
    size: Any = None
    prot: Any = None


@dataclass
class SigAction(Node):
    """sig:action signo, handler_label — minimal rt_sigaction (SA_RESTORER-less best-effort)."""
    signo: Any = None
    handler: str = ""  # label name or 0/SIG_DFL/SIG_IGN as number path


@dataclass
class SigReturn(Node):
    """sig:return — rt_sigreturn"""
    pass


@dataclass
class CpuAdc(Node):
    dest: str = "reg1"
    src: str = "reg2"

@dataclass
class CpuSbb(Node):
    dest: str = "reg1"
    src: str = "reg2"

@dataclass
class CpuBswap(Node):
    dest: str = "reg1"

@dataclass
class CpuFlagOp(Node):
    op: str = "clc"  # clc stc cmc cld std pause int3 ud2 leave cqo cdq

@dataclass
class CpuMulDiv1(Node):
    op: str = "mul"  # mul div
    src: str = "reg2"

@dataclass
class CpuTestImm(Node):
    dest: str = "reg1"
    imm: int = 0

@dataclass
class CpuBitOp(Node):
    op: str = "bts"  # bts btr btc
    base: str = "reg1"
    offset: str = "reg2"

@dataclass
class CpuPopcnt(Node):
    dest: str = "reg1"
    src: str = "reg2"

@dataclass
class CpuLzcnt(Node):
    dest: str = "reg1"
    src: str = "reg2"

@dataclass
class CpuTzcnt(Node):
    dest: str = "reg1"
    src: str = "reg2"


@dataclass
class CpuMovsxd(Node):
    dest: str = "reg1"
    src: str = "reg2"


@dataclass
class CpuShlx(Node):
    dest: str = "reg1"
    src: str = "reg2"
    cnt: str = "reg3"

@dataclass
class CpuShrx(Node):
    dest: str = "reg1"
    src: str = "reg2"
    cnt: str = "reg3"

@dataclass
class CpuSarx(Node):
    dest: str = "reg1"
    src: str = "reg2"
    cnt: str = "reg3"

@dataclass
class CpuRorx(Node):
    dest: str = "reg1"
    src: str = "reg2"
    imm: int = 0

@dataclass
class CpuBextr(Node):
    dest: str = "reg1"
    src: str = "reg2"
    ctrl: str = "reg3"

@dataclass
class CpuBlsi(Node):
    dest: str = "reg1"
    src: str = "reg2"

@dataclass
class CpuBlsr(Node):
    dest: str = "reg1"
    src: str = "reg2"

@dataclass
class CpuBlsmsk(Node):
    dest: str = "reg1"
    src: str = "reg2"

@dataclass
class CpuAdcx(Node):
    dest: str = "reg1"
    src: str = "reg2"

@dataclass
class CpuAdox(Node):
    dest: str = "reg1"
    src: str = "reg2"

@dataclass
class CpuCrc32(Node):
    dest: str = "reg1"
    src: str = "reg2"

@dataclass
class CpuRdrand(Node):
    dest: str = "reg1"

@dataclass
class CpuRdseed(Node):
    dest: str = "reg1"


@dataclass
class CpuPext(Node):
    dest: str = "reg1"
    src: str = "reg2"
    mask: str = "reg3"

@dataclass
class CpuPdep(Node):
    dest: str = "reg1"
    src: str = "reg2"
    mask: str = "reg3"

@dataclass
class CpuMulx(Node):
    dest_hi: str = "reg1"
    dest_lo: str = "reg2"
    src: str = "reg3"

@dataclass
class CpuCmpxchg(Node):
    dest: str = "reg1"
    src: str = "reg2"

@dataclass
class CpuPrefetch(Node):
    kind: str = "nta"  # nta w
    base: str = "reg1"

@dataclass
class CpuClflush(Node):
    base: str = "reg1"


@dataclass
class CpuMovzx(Node):
    dest: str = "reg1"
    src: str = "reg2"
    width: int = 8  # 8 or 16

@dataclass
class CpuMovsx(Node):
    dest: str = "reg1"
    src: str = "reg2"
    width: int = 8

@dataclass
class CpuBitImm(Node):
    op: str = "bt"  # bt bts btr btc
    base: str = "reg1"
    imm: int = 0

@dataclass
class CpuShldImm(Node):
    dest: str = "reg1"
    src: str = "reg2"
    imm: int = 0

@dataclass
class CpuShrdImm(Node):
    dest: str = "reg1"
    src: str = "reg2"
    imm: int = 0

@dataclass
class CpuNopLong(Node):
    pass

@dataclass
class CpuEnter(Node):
    size: int = 0
    nesting: int = 0


@dataclass
class CpuImul3(Node):
    dest: str = "reg1"
    src: str = "reg2"
    imm: int = 0

@dataclass
class CpuMxcsr(Node):
    op: str = "ld"  # ld st
    base: str = "reg1"

@dataclass
class CpuFx(Node):
    op: str = "save"  # save restore
    base: str = "reg1"

@dataclass
class CpuXgetbv(Node):
    pass

@dataclass
class CpuFsGs(Node):
    op: str = "rdfsbase"  # rdfsbase rdgsbase wrfsbase wrgsbase
    reg: str = "reg1"

@dataclass
class CpuPrivOp(Node):
    """privileged / system — emit only; may #GP in userspace"""
    op: str = "sldt"
    reg: str = "reg1"


@dataclass
class CellMapFile(Node):
    """cell:mapfile dest = size, fd [, offset [, prot]] — file-backed mmap."""
    dest: str = "reg1"
    size: Any = None
    fd: Any = None
    offset: Any = None
    prot: Any = None


@dataclass
class ThreadJoinAll(Node):
    """thread:join_all — wait until all spawned workers signal done."""
    pass


@dataclass
class NetPoll(Node):
    """net:poll fds_ptr, nfds, timeout_ms — poll(2); result in rax."""
    fds: Any = None
    nfds: Any = None
    timeout: Any = None


@dataclass
class NetEpollCreate(Node):
    dest: str = "reg1"
    flags: Any = None


@dataclass
class NetEpollCtl(Node):
    epfd: Any = None
    op: Any = None
    fd: Any = None
    event_ptr: Any = None


@dataclass
class NetEpollWait(Node):
    dest: str = "reg1"
    epfd: Any = None
    events: Any = None
    maxevents: Any = None
    timeout: Any = None


@dataclass
class ChipSerialInit(Node):
    """chip:serial_init — COM1 115200 8N1 minimal init"""
    pass


@dataclass
class ChipSerialPutc(Node):
    """chip:serial_putc value — poll COM1 and out byte"""
    value: Any = None


@dataclass
class ChipLidt(Node):
    """chip:lidt base_reg — lidt [base] (base points to 10-byte IDTR)"""
    base: str = "reg1"


@dataclass
class ChipLgdt(Node):
    """chip:lgdt base_reg — lgdt [base]"""
    base: str = "reg1"


@dataclass
class KernelHeapInit(Node):
    """kernel:heap_init size — bump allocator over data:alloc __kheap"""
    size: int = 4096


@dataclass
class KernelHeapAlloc(Node):
    """kernel:heap_alloc dest = size"""
    dest: str = "reg1"
    size: Any = None


@dataclass
class KernelCtxSave(Node):
    """kernel:ctx_save dest_reg — store rax..r15 at [dest] (128 bytes)"""
    dest: str = "reg1"


@dataclass
class KernelCtxLoad(Node):
    """kernel:ctx_load src_reg — load rax..r15 from [src] (does not restore rsp safely mid-way)"""
    src: str = "reg1"


@dataclass
class ChipKbdPoll(Node):
    """chip:kbd_poll dest — if key ready, AL=scancode else 0"""
    dest: str = "reg1"


@dataclass
class ChipInt(Node):
    """chip:int n — software interrupt"""
    vec: int = 0


@dataclass
class KernelIdtInstall(Node):
    """kernel:idt_install — build default IDT + load (all vectors → isr_default)"""
    pass


@dataclass
class ChipPitInit(Node):
    """chip:pit_init divisor — PIT ch0 mode3, divisor 1..65535"""
    divisor: int = 11932  # ~100Hz


@dataclass
class ChipPicRemap(Node):
    """chip:pic_remap — master 0x20, slave 0x28"""
    pass


@dataclass
class KernelCoopSwitch(Node):
    """kernel:coop_switch save_reg, load_reg — ctx_save then ctx_load"""
    save: str = "reg1"
    load: str = "reg2"


@dataclass
class KernelPrintkStr(Node):
    """kernel:printk_str label — serial_putc each byte until NUL"""
    src: Any = None


@dataclass
class KernelPanic(Node):
    """kernel:panic — cli; optional serial 'P'; halt loop"""
    pass


@dataclass
class KernelTickInstall(Node):
    """kernel:tick_install — IRQ0 stub increments __tick, sends PIC EOI, iretq"""
    pass


@dataclass
class KernelTickRead(Node):
    """kernel:tick_read dest"""
    dest: str = "reg1"


@dataclass
class KernelRamfsInit(Node):
    """kernel:ramfs_init — 8 slots name[16]+ptr+len"""
    pass


@dataclass
class KernelRamfsPut(Node):
    """kernel:ramfs_put name_str, data_reg, len"""
    name: Any = None
    data: Any = None
    length: Any = None


@dataclass
class KernelRamfsGet(Node):
    """kernel:ramfs_get dest = name_str — dest=ptr or 0"""
    dest: str = "reg1"
    name: Any = None


@dataclass
class KernelNetInit(Node):
    pass


@dataclass
class KernelNetPoll(Node):
    """kernel:net_poll dest — stub returns 0 (no packet)"""
    dest: str = "reg1"


@dataclass
class KernelCsRing(Node):
    """kernel:cs_ring dest — CS & 3 (privilege)"""
    dest: str = "reg1"


@dataclass
class KernelEnterUser(Node):
    """kernel:enter_user entry, stack — iretq to ring3 (CS=0x1B SS=0x23)"""
    entry: Any = None
    stack: Any = None


@dataclass
class KernelPfInstall(Node):
    """kernel:pf_install — vector 14 -> cli;hlt (or serial 'F')"""
    pass


@dataclass
class KernelNetAllowPort(Node):
    """kernel:net_allow_port n — set bit in allow bitmap (0..63)"""
    port: int = 0


@dataclass
class KernelNetCheckPort(Node):
    """kernel:net_check_port dest = n — 1 if allowed, 0 deny"""
    dest: str = "reg1"
    port: Any = None


@dataclass
class KernelPreemptArm(Node):
    """kernel:preempt_arm ctx_reg — IRQ0 will set __preempt_req = ctx (cooperative hint)"""
    ctx: str = "reg1"


@dataclass
class KernelSyscallInit(Node):
    """kernel:syscall_init — EFER.SCE + STAR + LSTAR=__syscall_entry + FMASK"""
    pass


@dataclass
class KernelSysret(Node):
    """kernel:sysret — rcx=user RIP must be set; r11=rflags; sysretq"""
    pass


@dataclass
class KernelNicBar(Node):
    """kernel:nic_bar addr — set MMIO base for nic_reg_*"""
    addr: Any = None


@dataclass
class KernelNicRegRead(Node):
    """kernel:nic_reg_read dest = offset"""
    dest: str = "reg1"
    offset: Any = None


@dataclass
class KernelNicRegWrite(Node):
    """kernel:nic_reg_write offset = value"""
    offset: Any = None
    value: Any = None


@dataclass
class KernelIrqFullSave(Node):
    """kernel:irq_full_save_on — IRQ0 saves rax..r15 to __irq_gprs before tick"""
    pass


@dataclass
class KernelSyscallTableInit(Node):
    """kernel:syscall_table_init — 64 slots, default __nosys"""
    pass


@dataclass
class KernelSyscallRegister(Node):
    """kernel:syscall_register nr, handler_label"""
    nr: int = 0
    handler: str = ""


@dataclass
class KernelNmiInstall(Node):
    """kernel:nmi_install — IDT[2] -> cli;hlt"""
    pass


@dataclass
class KernelDmaRingInit(Node):
    """kernel:dma_ring_init slots — power-of-2 slots x 16-byte descriptors"""
    slots: int = 16


@dataclass
class KernelDmaRingPush(Node):
    """kernel:dma_ring_push addr, len — returns 0 ok / 1 full in reg1"""
    addr: Any = None
    length: Any = None


@dataclass
class KernelDmaRingPop(Node):
    """kernel:dma_ring_pop dest_addr, dest_len — 0 ok / 1 empty in reg1"""
    dest_addr: str = "reg2"
    dest_len: str = "reg3"
