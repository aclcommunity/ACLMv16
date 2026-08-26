# ACLM audit v0.12.6

## Critical bugs found and fixed

### 1. SHLD/SHRD clobbered CL (CRITICAL) — FIXED
Codegen did `mov rcx, src` before `shld dest, src`, destroying the shift count in CL.
User must set `rcx`/`CL` themselves; codegen must not overwrite.
Regression: `test_280_shld_cl_preserve.aclm`, strengthened `test_200`.

### 2. Duplicate encoder methods — FIXED
Second definitions of `leave`, `cld`, `std`, `lfence`, `sfence`, `mfence` removed
(Python last-def-wins; cleaned to avoid drift).

### 3. cmpxchg + reg1 alias (FOOTGUN, not encoding bug)
`reg1` maps to `rax`. Using `cpu:set rax` then `cpu:set reg1` overwrites the same register.
`cmpxchg` tests updated to use `reg2`/`reg3` for operands.
Regression: `test_281_cmpxchg_fail.aclm`, `test_282_reg1_is_rax.aclm`.

## Verified green
- Full suite 102/102
- big_realworld, realworld_big demos

## Design notes (not bugs)
- Virtual map: reg1=rax … reg13=r14; r15 scratch; rbp/rsp reserved
- Privileged ops encode-only in userspace (build-only tests)
- Full x86 ISA still not named; use `raw:`
