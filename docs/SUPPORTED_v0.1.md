# ACLM Supported Ops — v0.1.0 (LOCKED)

This surface is **hardcore-tested**. Anything not listed is **out of scope** for v0.1.

## Registers
- Virtual: `reg1` … `reg14`
- Physical aliases: `rax rbx rcx rdx rsi rdi r8` … `r15`
- Reserved (illegal as dest): `rbp rsp rip`

## CPU
- Binary: `set add sub mul div mod and or xor shl shr rol ror`
- Unary: `not neg inc dec`
- Shift count: immediate or register
- `cmp` left, right
- Conditions for `jump_if`: `eq neq lt gt lte gte` (+ encoder set: above/below where applicable)

## Memory
- `data:alloc name = size`
- `data:const name = int | "string"`
- `ram:read` / `read8` / `read16` / `read32` / `read64`
- `ram:write` / `write8` / `write16` / `write32` / `write64`
- Form: `[base + offset]` where base is reg or data label

## Control
- `~label`, `goto ~label`, `jump_if cond ~label`
- `call ~label [args…]`, `ret`
- `stack:push`, `stack:pop`

## Syscalls
- `sys:call <number|name> [args…]`
- Names: read write open close lseek/seek mmap mprotect munmap exit exit_group getpid fork wait4 nanosleep clock_gettime socket connect sendto recvfrom bind listen ioctl brk

## Guarantees (v0.1)
1. High-register zero (`xor r8–r15`) encodes with correct REX
2. Data-label stores do not clobber live `reg11` (r12) permanently
3. Integer `data:const` used as operand yields **value**; string yields **address**
4. Invalid reg / op / syscall → hard error (no silent wrong code)
5. Regression: `python3 tests/run_all.py` → 20/20

## Explicitly NOT in v0.1
mem:set/copy, str:*, FPU, SIMD, threads, net wrappers, structs, optimizer, baremetal

---

## Stage-2 additions (v0.2 metal control) — HARDENED 28/28

### Unique full-control syntax

| Op | Meaning |
|----|---------|
| `blast:fill dest = byte, len` | Byte fill; **dest reg preserved** |
| `blast:copy dest = src, len` | Byte copy |
| `wire:len dest = src` | NUL-terminated length |
| `wire:cmp dest = a, b` | 0 if equal, 1 else |
| `wire:copy dest = src` | Copy including NUL |
| `wire:emit src [, len]` | write to stdout (len optional → auto) |
| `trap:neg ~label` | Jump if `rax < 0` (syscall error) |

### Aliases
- `mem:set` / `mem:copy` → blast fill/copy  
- `str:len` / `str:cmp` / `str:copy` / `str:print` → wire  
- `err:check ~label` → trap:neg  

### Guarantees
- Fill length 0 is no-op  
- Fill does not clobber destination pointer register  
- r11–r13 saved/restored around blast/wire helpers  

---

## Stage-3 additions (v0.3 metal OS surface) — HARDENED 54/54

| Op | Meaning |
|----|---------|
| `cell:map dest = size` | anonymous RW mmap |
| `cell:free ptr, size` | munmap |
| `gate:cas addr = expected, desired` | lock cmpxchg; preserves non-involved regs |
| `gate:spin addr` | spin until free then take (set 1) |
| `pulse:sleep ns` | nanosleep (nsec field, sec=0) |
| `pulse:now dest` | CLOCK_MONOTONIC seconds |

### Guarantees
- gate:* does not permanently clobber `reg1`/`rax` unless it is the address/expected operand
- cell:map returns MAP_FAILED-compatible negative on failure (use trap:neg)
- All prior tests still green

---

## Stage-4 hardware control — HARDENED 63/63

| Op | Meaning |
|----|---------|
| `flag:setcc dest = cond` | SETcc after cmp (eq/neq/lt/gt/…) |
| `chip:ticks dest` | RDTSC low bits |
| `chip:id leaf [a b c d]` | CPUID → 4 regs (default reg1..4) |
| `chip:cli` / `sti` / `halt` | privileged (build-tested) |
| `gate:fence [mfence\|lfence\|sfence]` | memory barrier |
| `port:out port = val` / `port:in dest = port` | privileged I/O |
| `vec:load/store/addps/subps/mulps/divps` | SSE |
| `cpu:lea dest = [base+off]` | address calc |
| `sys:call <num> …` | raw syscall number |

Interop test `test_77` exercises flags+ticks+cpuid+fence+lea+cas+pulse+cell+vec together.


---
**Updated:** see `SUPPORTED_v0.8.md` and root `README.md` for v0.8.
