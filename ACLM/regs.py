"""Register map — virtual names and hardware names.

Virtual reg1..reg12 map to a fixed physical set.
r11 and r15 are INTERNAL scratches (not user-visible virtual names).
rbp/rsp/rip reserved.
"""

from typing import Dict

VIRTUAL: Dict[str, str] = {
    "reg1": "rax", "reg2": "rbx", "reg3": "rcx", "reg4": "rdx",
    "reg5": "rsi", "reg6": "rdi", "reg7": "r8", "reg8": "r9",
    "reg9": "r10",
    # r11 is internal temp (SECOND_SCRATCH) — skipped
    "reg10": "r12", "reg11": "r13", "reg12": "r14",
}

# compat: reg13 was old name for r14 — map to reg12 physical
VIRTUAL_COMPAT: Dict[str, str] = {
    "reg13": "r14",  # deprecated alias
}

PARTIAL32: Dict[str, str] = {
    "eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
    "esi": "rsi", "edi": "rdi",
    "r8d": "r8", "r9d": "r9", "r10d": "r10",
    "r12d": "r12", "r13d": "r13", "r14d": "r14",
}

PHYSICAL = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
    "r8", "r9", "r10", "r12", "r13", "r14",
}

RESERVED = {"rbp", "rsp", "rip", "r15", "r11", "esp", "ebp"}

SYSCALL_ARGS = ["rdi", "rsi", "rdx", "r10", "r8", "r9"]
SCRATCH = "r15"
SECOND_SCRATCH = "r11"  # codegen temps; never a virtual reg


def resolve(name: str) -> str:
    n = name.strip().lower()
    if n in RESERVED:
        raise ValueError(f"register '{name}' is reserved (stack/scratch/IP)")
    if n in VIRTUAL:
        return VIRTUAL[n]
    if n in VIRTUAL_COMPAT:
        return VIRTUAL_COMPAT[n]
    if n in PARTIAL32:
        return PARTIAL32[n]
    if n in PHYSICAL:
        return n
    raise ValueError(f"unknown register '{name}'")


def is_reg_name(name: str) -> bool:
    n = name.strip().lower()
    return n in VIRTUAL or n in VIRTUAL_COMPAT or n in PHYSICAL or n in PARTIAL32


def is_partial32(name: str) -> bool:
    return name.strip().lower() in PARTIAL32
