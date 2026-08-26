# Deep audit v0.12.7

## Method
- Full suite
- Adversarial probes: arith, mem 8/64, jcc signed/unsigned, stack, thread, macro,
  all virtual regs, mmap preserve, fn callee-save, rol/sar/shl, demos
- Static scan encoder/codegen

## Bugs fixed this pass
1. **JCC `abe` wrong opcode** (was 0x86 jbe, should be 0x83 jae) — FIXED
2. Prior: SHLD CL clobber (0.12.6)

## Regression tests added
- test_290_jcc_unsigned, test_291_jcc_signed
- test_292_stack_push_pop, test_293_all_regs_sum

## Result
106/106 suite pass + adversarial probes green + both demos OK

## Remaining risk (honest)
- Not every rare ISA encoding proven correct on all CPUs
- Privileged ops userspace #GP expected
- "Zero bugs forever" impossible; this is deep verified for current surface
