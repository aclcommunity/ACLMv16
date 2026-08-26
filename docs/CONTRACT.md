# ACLM contract (v0.14.1) — control / safety / clarity

## Register map (virtual → physical)

| Virtual | Physical | Notes |
|---------|----------|--------|
| reg1 | rax | return value; cmpxchg implicit; mul/div low |
| reg2 | rbx | callee-saved across `fn` |
| reg3 | rcx | **shift count** for shld/shrd; syscall arg4 is r10 not rcx |
| reg4 | rdx | mul/div high; syscall arg3 |
| reg5 | rsi | syscall arg2 |
| reg6 | rdi | syscall arg1; `fn` first arg |
| reg7 | r8 | syscall arg5 |
| reg8 | r9 | syscall arg6 |
| reg9 | r10 | syscall arg4 |
| reg10 | r11 | caller-saved / temp |
| reg11 | r12 | callee-saved |
| reg12 | r13 | callee-saved |
| reg13 | r14 | callee-saved |
| *(scratch)* | r15 | codegen scratch — do not rely on live values across ops |
| *(frame)* | rbp | frame pointer when `local:` used |
| *(stack)* | rsp | stack pointer |

32-bit names (`eax`, `ebx`, …) alias the same 64-bit register (write zero-extends).

## Calling convention (`fn` / `call`)

- Args: SysV order **rdi, rsi, rdx, rcx, r8, r9** (first six)
- Return: **rax** (`reg1`)
- Callee-saved preserved across ACLM `fn`: rbx, r12–r14, rbp
- Scratch may clobber: rax, rcx, rdx, rsi, rdi, r8–r11, r15

## Syscall

- `sys:call name|nr args…` → Linux x86-64: **rax**=nr, **rdi rsi rdx r10 r8 r9**
- Prefer named calls (`exit`, `write`, `mmap`, …) when available

## Flags

- `cmp` / `test` / ALU: write status flags
- `jump_if` / `flag:setcc` / `cpu:cmov`: **read** flags from the last flag-writing op
- `mov` / `lea` / `movzx`: flags intact
- After `flag:setcc`, do not assume previous cmp flags remain if you `cmp` the result

## Memory widths

- `ram:read8/16/32` / `write8/16/32` — exact width
- 64-bit `ram:read` / `ram:write` — full register
- Struct fields: offsets in `--teach` listing and error messages

## Systems (v0.14 Priority B)

| API | Meaning | Safety note |
|-----|---------|-------------|
| `cell:mapfile` | file-backed mmap | fd must be valid; MAP_PRIVATE |
| `thread:join_all` | wait until done ≥ spawn | **not** waitid(tid); counter-based |
| `net:poll` | poll(2) | |
| `net:epoll_*` | epoll_create1/ctl/wait | |

## Strict mode

```bash
python3 -m aclm.compiler build file.aclm --strict   # ERRORs → exit 2
python3 -m aclm.compiler check file.aclm --warn     # print WARN/NOTE
```

**ERROR examples:** `cpu:shld` with `reg3`/`rcx` as data operand.

**WARN examples:** `cmpxchg`+`reg1`, `mulu`+`reg1`/`reg4`, dual `reg1`+`rax` in one file.

## Escape hatch

`raw: …` bytes and documented `raw:begin`/`raw:end` (if present) = full ISA ceiling.

## Macros (v0.14.2)

```aclm
macro: name arg1 arg2
...body using $arg1 $arg2...
end:macro

name val1 val2   # call
```

- Expansion is text-substitution, run before local-label expansion and codegen.
- **Nested calls work:** a macro body may call another macro (fixed-point
  expansion, max 64 passes; a macro that invokes itself directly or
  indirectly is a hard error, not a hang).
- **Repeated calls are label-safe:** any `~@name` local label inside a
  macro body gets a call-site-unique suffix at expansion time, so calling
  the same macro more than once in one file never collides.
- Missing-argument calls fail with `file:line: macro 'name': need N
  arg(s) (...), got M` — same `file:line` shape as other compiler errors.
