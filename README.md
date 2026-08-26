# ACLM — Aryan's Coding Language of Metal/Hardware

**Manual-first metal. Direct x86-64 ELF. Maximum practical control.**

**Version: 0.16.0** — Freestanding/kernel tiers on metal core (Multiboot→long mode, serial, IDT/GDT, heap/ctx, PIT/PIC, labs)

| Pillar | Target | How |
|--------|--------|-----|
| **Control** | exact ops + listing | `raw:`, width-exact RAM, `--teach` |
| **Power** | real Linux metal | ISA 0.12 + mapfile/poll/epoll/join_all |
| **Safety** | footguns caught | `--strict` / `--warn` (see `docs/CONTRACT.md`) |
| **Clarity** | one contract | this README + CONTRACT + tests |

---

## Quick start

```bash
python3 -m aclm.compiler --version
python3 -m aclm.compiler run tests/test_01_hello.aclm
python3 -m aclm.compiler build file.aclm -o ./out --strict --teach
python3 tests/run_all.py
```

---

## Register truth (memorize)

```
reg1=rax  reg2=rbx  reg3=rcx  reg4=rdx  reg5=rsi  reg6=rdi
reg7=r8   reg8=r9   reg9=r10  reg10=r11 reg11=r12 reg12=r13 reg13=r14
SCRATCH=r15   frame=rbp when locals   stack=rsp
```

**Never** assume `reg1` and `rax` are different. Use `--strict`.

---

## Surface (what ships)

- **Core:** cpu/ram/stack, jumps, labels, macros, include  
- **Structure:** struct, fn, local, expressions  
- **Metal helpers:** cell, blast, wire, gate, pulse, chip, port, vec/avx  
- **ISA 0.12:** adc/sbb, BMI, mulx, cmpxchg, shifts, fences, movzx/sx, …  
- **Systems 0.14:** `cell:mapfile`, `thread:join_all`, `net:poll`, `net:epoll_*`  
- **Teach:** `--teach` listing · labs/ · std/

Full rules: **`docs/CONTRACT.md`**.  
ISA named list: **`docs/ISA_EXPANSION_v0.12.md`**.  
Systems: **`docs/PRIORITY_B_v0.14.md`**.
Kernel/freestanding: **`docs/KERNEL_CONTRACT.md`**.

---

## Calling contract

- Args SysV: rdi…r9 · ret rax  
- Callee-saved across fn: rbx, r12–r14, rbp  
- r15 scratch · rbp/rsp reserved  

---

## Philosophy

Manual core first. Helpers optional. `raw:` is the ISA ceiling.  
Strict mode documents the machine — it does not hide it.

---

## Test suite

```bash
python3 tests/run_all.py
```

---

## Version

**0.16.0** (single source: `aclm/compiler.py` → `VERSION`)

- Base: 0.14.x userspace metal + macros + systems
- Kernel: `docs/KERNEL_CONTRACT.md` (Tier-1… baremetal stack)
- Tests: `python3 tests/run_all.py` (137+; QEMU smoke if installed)
