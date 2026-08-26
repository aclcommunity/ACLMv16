"""ACLM strict / alias analysis — safety rails for virtual↔physical footguns.

Design:
  - severity "error"  → build/check --strict exits 2
  - severity "warning"→ always printed when analyze is run; strict still exits 0
  - severity "note"   → educational only

Virtual map (see regs.py):
  reg1=rax reg2=rbx reg3=rcx reg4=rdx reg5=rsi reg6=rdi
  reg7=r8  reg8=r9  reg9=r10 reg10=r11 reg11=r12 reg12=r13 reg13=r14
  r15=SCRATCH  rbp/rsp reserved
"""

from __future__ import annotations
from typing import List, Tuple
import re

from .regs import VIRTUAL

# physical → primary virtual name
PHYS_TO_VIRT = {
    "rax": "reg1", "rbx": "reg2", "rcx": "reg3", "rdx": "reg4",
    "rsi": "reg5", "rdi": "reg6",
    "r8": "reg7", "r9": "reg8", "r10": "reg9", "r11": "reg10",
    "r12": "reg11", "r13": "reg12", "r14": "reg13",
}

# ops that implicitly use fixed hardware regs
IMPLICIT = {
    "cpu:shld": ("rcx", "shift count in CL/RCX"),
    "cpu:shrd": ("rcx", "shift count in CL/RCX"),
    "cpu:mulu": ("rax/rdx", "unsigned mul uses RDX:RAX"),
    "cpu:divu": ("rax/rdx", "unsigned div uses RDX:RAX"),
    "cpu:imul": ("rax/rdx", "some imul forms use RDX:RAX"),
    "cpu:cmpxchg": ("rax", "compare operand is RAX"),
    "cpu:mulx": ("rdx", "mulx uses RDX source"),
    "cpu:cqo": ("rax/rdx", "sign-extends RAX into RDX"),
    "cpu:cdq": ("eax/edx", "sign-extends EAX into EDX"),
    "cpu:cwd": ("ax/dx", "sign-extends AX into DX"),
}


def _word(text: str, word: str) -> bool:
    return re.search(rf"(?<![\w]){re.escape(word)}(?![\w])", text) is not None


def analyze_source(src: str) -> List[Tuple[str, str]]:
    """Return list of (severity, message)."""
    out: List[Tuple[str, str]] = []
    used_virtual: set = set()
    used_phys: set = set()

    for i, line in enumerate(src.splitlines(), 1):
        low = line.split("#")[0].lower().strip()
        if not low:
            continue

        for v in VIRTUAL:
            if _word(low, v):
                used_virtual.add(v)
        for p in PHYS_TO_VIRT:
            if _word(low, p):
                used_phys.add(p)

        # --- hard errors (strict exit 2) ---
        if ("cpu:shld" in low or "cpu:shrd" in low):
            if _word(low, "reg3") or _word(low, "rcx") or _word(low, "ecx"):
                # reg3/rcx as *data* operand is almost always wrong when also count
                out.append((
                    "error",
                    f"line {i}: shld/shrd — reg3/rcx is the shift-count register; "
                    f"do not use it as a data operand (use reg2/reg11/…)",
                ))

        # --- warnings ---
        if "cpu:cmpxchg" in low and (_word(low, "reg1") or _word(low, "rax") or _word(low, "eax")):
            out.append((
                "warning",
                f"line {i}: cmpxchg — RAX/reg1 is the implicit compare target",
            ))
        if ("cpu:mulu" in low or "cpu:divu" in low):
            if _word(low, "reg1") or _word(low, "reg4") or _word(low, "rax") or _word(low, "rdx"):
                out.append((
                    "warning",
                    f"line {i}: mulu/divu — destroys RDX:RAX (reg4:reg1); save first if needed",
                ))
        if "cpu:mulx" in low and (_word(low, "reg4") or _word(low, "rdx")):
            out.append((
                "warning",
                f"line {i}: mulx — RDX is implicit source; avoid clobber patterns",
            ))
        if "sys:call" in low or "sys:raw" in low:
            # educational note once per file handled below
            pass

        # thread join_all semantics
        if "thread:join_all" in low:
            out.append((
                "note",
                f"line {i}: thread:join_all waits on spawn/done counters — not waitid(tid)",
            ))

    # dual naming same physical
    for phys, virt in PHYS_TO_VIRT.items():
        if phys in used_phys and virt in used_virtual:
            out.append((
                "warning",
                f"file uses both '{virt}' and '{phys}' (identical physical register)",
            ))

    # if any syscall, one file-level note
    if re.search(r"sys:\s*(call|raw)", src, re.I):
        out.append((
            "note",
            "syscalls use Linux x86-64 ABI: rax=nr, args rdi rsi rdx r10 r8 r9 "
            "(reg1/reg6/reg5/reg4/reg9/reg7/reg8 — see docs/CONTRACT.md)",
        ))

    # dedupe identical messages
    seen = set()
    uniq: List[Tuple[str, str]] = []
    for sev, msg in out:
        key = (sev, msg)
        if key not in seen:
            seen.add(key)
            uniq.append((sev, msg))
    return uniq


def format_warnings(ws: List[Tuple[str, str]]) -> str:
    order = {"error": 0, "warning": 1, "note": 2}
    ws = sorted(ws, key=lambda x: order.get(x[0], 9))
    lines = []
    for sev, msg in ws:
        tag = {"error": "ERROR", "warning": "WARN", "note": "NOTE"}.get(sev, sev)
        lines.append(f"[ACLM strict {tag}] {msg}")
    return "\n".join(lines)


def has_errors(ws: List[Tuple[str, str]]) -> bool:
    return any(s == "error" for s, _ in ws)
