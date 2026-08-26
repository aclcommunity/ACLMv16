# ACLM ISA expansion (v0.12.x)

## Philosophy
Named forms for high-use ops. Remainder: `raw:begin` … `raw:end`.

## Batches

### 0.12.0
adc, sbb, bswap, clc/stc/cmc/cld/std/pause/cqo/cdq/leave,
mulu, divu, testimm, bts/btr/btc, popcnt, lzcnt, tzcnt,
shld/shrd, imulimm, andn, bzhi, cmovmem, cmpxchg16b

### 0.12.1
sar, rcl, rcr, cdqe, movsxd, pushfq, popfq,
rdtscp, lfence, sfence, mfence, endbr64

### 0.12.2
shlx, shrx, sarx, rorx, bextr, blsi, blsr, blsmsk,
adcx, adox, crc32, rdrand, rdseed, sal

### 0.12.3
pext, pdep, mulx, cmpxchg (reg),
prefetch nta/w, clflush, cbw, cwde, cwd

## Still not named (use raw:)
x87 stack, full AVX-512, most system/VMX/SGX, obscure legacy


### 0.12.4
movzx, movsx (8/16),
btimm/btsimm/btrimm/btcimm,
shldimm, shrdimm,
rcl/rcr with CL,
nopl (long NOP), enter


### 0.12.5
imul3 (r,r,imm), ldmxcsr, stmxcsr, fxsave, fxrstor, xgetbv,
rdfsbase/rdgsbase/wrfsbase/wrgsbase (FSGSBASE),
privileged encode: sldt, str, smsw, swapgs, rdmsr, wrmsr, rdpmc, clts, wbinvd, sysret, sysenter, sysexit

## Honest remaining (use raw:)
- Full AVX-512 / AMX map
- Full x87 stack ops
- Most VMX / SGX / CET deeper forms
- Every ModRM/mem variant of every insn
