# ACLM

**Aryan’s Coding Language of Metal** — a manual-first systems language that compiles source directly to x86-64 machine code and ELF binaries. Encoding and image writing are implemented in-process; the default path is self-contained: source in, binary out.

**Version 0.16.0**

| | |
|---|---|
| **Targets** | Linux userspace (ELF64) · freestanding Multiboot / long mode (ELF32) |
| **Output** | Native binaries via the in-tree x86-64 encoder and ELF writers |
| **Philosophy** | Maximum practical control · honest about the machine · `raw:` as the ISA ceiling |

```bash
python3 -m aclm.compiler run tests/test_01_hello.aclm
python3 tests/run_all.py
```

---

## What ACLM is

ACLM is a **metal** language: registers, memory widths, flags, and control flow stay explicit. Programs map closely to the instructions and structures the CPU executes.

- **Named metal operations** for everyday instructions and platform surfaces  
- **Explicit registers and operand widths** — no hidden allocation policy  
- **Direct ELF emission** from the compiler pipeline  
- **`--teach` listings** that map each source line to bytes, stack frames, and flag notes  
- **`raw:`** when a sequence must be expressed as exact bytes  

The design goal is control you can see and verify — not abstraction that erases the machine.

---

## Features at a glance

### Userspace (Linux x86-64)

- Virtual registers `reg1`…`reg13` and physical aliases, with documented scratch and frame usage  
- Memory access with exact widths (`read8` / `16` / `32` / `64` and writes)  
- Control flow: labels, `goto`, `jump_if`, comparisons, `flag:setcc`, `cmov`  
- Structs, functions, locals, and expressions  
- Macros with nested expansion and call-site-unique local labels  
- Platform surfaces: syscalls, `wire:`, `cell:` (including file-backed map), threads, `net:poll` / `epoll_*`  
- Extended ISA batch (shifts, bit manipulation, selected atomics-oriented ops); everything else via `raw:`  
- Optional W^X layout, debug map hooks, and `--strict` register-alias analysis  

### Freestanding / kernel-oriented

- `target:baremetal` produces a Multiboot1 ELF32 image with a 32-bit trampoline into 64-bit long mode  
- Identity map of the first 1 GiB (2 MiB pages), GDT load, serial COM1  
- Helpers: CLI / STI / HLT, `lidt` / `lgdt`, PIT / PIC, cooperative context switch, bump heap, ramfs demo, printk / panic  
- QEMU-bootable MiniOS lab (serial scripted demo)  

Full freestanding rules: [`docs/KERNEL_CONTRACT.md`](docs/KERNEL_CONTRACT.md).

---

## Quick start

### Requirements

- Python 3.10+ (host runner for the compiler)  
- Linux x86-64 as the primary execution environment  
- Optional: `qemu-system-x86_64` for freestanding smoke tests  

### Build and run (userspace)

```bash
python3 -m aclm.compiler --version
python3 -m aclm.compiler build program.aclm -o ./program
./program

python3 -m aclm.compiler run program.aclm
```

### Teaching listing

```bash
python3 -m aclm.compiler build program.aclm -o ./program --teach
# writes program.aclm.lst — registers, frames, bytes, hints
```

### Strict mode

```bash
python3 -m aclm.compiler build program.aclm -o ./program --strict
python3 -m aclm.compiler check program.aclm --warn
```

### Baremetal / MiniOS

```bash
python3 -m aclm.compiler build labs/minios_kernel.aclm -o minios.elf
qemu-system-x86_64 -kernel minios.elf -nographic -serial mon:stdio -no-reboot
```

### Test suite

```bash
python3 tests/run_all.py
```

When QEMU is installed, freestanding boot smoke tests run as part of the suite.

---

## Language surface (summary)

| Area | Examples |
|------|----------|
| Data | `data:alloc`, `data:const`, `data:bytes`, `data:align` |
| CPU | `cpu:set`, `cpu:add`, `cpu:lea`, `cmp`, `cpu:cmov`, shifts, bit ops |
| Memory | `ram:read` / `ram:write` and width-exact forms |
| Control | labels, `goto`, `jump_if`, `fn` / `call` / `ret`, macros |
| Structure | `struct:` … `end:struct`, field offsets in expressions |
| Linux surfaces | `sys:call`, `wire:emit`, `cell:map` / `mapfile`, `thread:*`, `net:poll` / `epoll_*` |
| Escape | `raw:` byte sequences |
| Freestanding | `target:baremetal`, `chip:*`, `kernel:*` |

### Register map

```text
reg1 = rax      reg2 = rbx      reg3 = rcx      reg4 = rdx
reg5 = rsi      reg6 = rdi      reg7 = r8       reg8 = r9
reg9 = r10      reg10 = r11     reg11 = r12     reg12 = r13
reg13 = r14
SCRATCH = r15
Frame pointer = rbp when function locals are used
Stack pointer = rsp
```

`reg1` and `rax` name the **same** physical register. Prefer one naming style per file; use `--strict` to catch mixed virtual and physical use.

Complete calling and flag rules: [`docs/CONTRACT.md`](docs/CONTRACT.md).

---

## Compiler pipeline

```text
.aclm source
    → lexer / parser (AST)
    → include resolution and macro expansion
    → codegen (registers, frames, platform or freestanding helpers)
    → x64enc (instruction bytes and relocations)
    → elfwriter
         → ELF64 for Linux userspace
         → Multiboot ELF32 + long-mode trampoline for baremetal
```

All stages live under `aclm/` in this repository.

---

## Design principles

1. **Manual core first** — helpers are optional; the machine model stays visible.  
2. **Named operations for the common path** — frequent instructions and platform entry points get clear syntax.  
3. **`raw:` is the ceiling** — any byte sequence the named surface omits can still be emitted.  
4. **No silent rewrite policy** — the compiler does not invent optimizations that discard intentional encoding.  
5. **Teach the machine** — listings, labs, and diagnostics exist to show what was emitted.  
6. **Stated limits** — freestanding support is aimed at small Multiboot kernels and teaching systems, not a general-purpose operating system product.

---

## Repository layout

```text
aclm/     compiler, encoder, ELF writers, Multiboot boot path
docs/     contracts, ISA notes, audits, kernel tiers
labs/     teaching labs and MiniOS / kernel examples
std/      small include macros (print, mem, exit)
tests/    regression suite (userspace, baremetal, optional QEMU smoke)
demos/    larger userspace demonstrations
```

---

## Status (0.16.0)

| Track | State |
|-------|--------|
| Linux userspace metal | Ready for teaching and systems experiments |
| Macro expansion | Nested and repeated calls supported with unique local labels |
| Strict / alias analysis | `--strict` and `--warn` |
| Freestanding boot | Multiboot → long mode; MiniOS verified under QEMU |
| Kernel-oriented helpers | Serial, IDT/GDT load, heap, coop switch, ramfs demo, PIT/PIC |
| Full operating system product | Out of scope for this version |

---

## Documentation

| Document | Contents |
|----------|----------|
| [`docs/CONTRACT.md`](docs/CONTRACT.md) | Registers, calling convention, flags, strict mode |
| [`docs/KERNEL_CONTRACT.md`](docs/KERNEL_CONTRACT.md) | Baremetal target, boot path, helper tiers |
| [`docs/ISA_EXPANSION_v0.12.md`](docs/ISA_EXPANSION_v0.12.md) | Named ISA groups versus `raw:` |
| [`docs/PRIORITY_B_v0.14.md`](docs/PRIORITY_B_v0.14.md) | mapfile, join_all, poll / epoll |
| [`docs/AUDIT_v0.14.2_macros.md`](docs/AUDIT_v0.14.2_macros.md) | Macro expansion correctness |

---

## Examples

**Userspace**

```aclm
data:const msg = "hello from ACLM\n"
wire:emit msg
sys:call exit 0
```

**Freestanding**

```aclm
target:baremetal
chip:serial_init
data:const hi = "BOOTOK\n"
kernel:printk_str hi
chip:halt
```

---

## Version

**0.16.0** — single source of truth: `VERSION` in `aclm/compiler.py`.

---

## Summary

ACLM is a metal systems language with explicit machine state, direct ELF output, Linux and Multiboot targets, teaching listings, and a `raw:` escape for full byte-level control — built so that what you write remains accountable to what the CPU runs.
