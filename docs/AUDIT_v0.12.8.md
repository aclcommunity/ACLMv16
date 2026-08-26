# Unique-program deep audit v0.12.8

## Method
30 unique programs (not repeated suite cases): fib, collatz, gcd, factorial,
checksum, bitrev, sieve mark, isqrt, det, mmap fill, two threads, macros,
adc multi-precision, stack depth, etc.

## Result
- 27/30 unique tests correct on first write
- 3 "failures" were **test author errors**, not compiler bugs:
  1. det2 — re-verified OK with safe regs
  2. isqrt — algorithm error in test; simple version OK
  3. shld4 — used `reg3` as src while `reg3`==`rcx` (count register)

## Compiler bugs found this pass
**None new.**

## Lesson
Virtual map: reg3=rcx, reg1=rax, reg4=rdx — footguns with mulu/shld/cmpxchg.

## Suite
107/107 after test_294
