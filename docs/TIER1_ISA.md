# ACLM Tier-1 ISA notes (v0.10)

## Added encodings
- shld / shrd (CL count)
- imul r64, imm32
- andn / bzhi (BMI)
- cmovcc from memory
- cmpxchg16b (LOCK form)
- lock: / rep: prefix statements
- raw:begin/end with hex-default numbers

## Full x86-64 ISA?
Not every opcode. Ceiling raised via `raw:` for anything missing.
Goal: common power ops + escape hatch, always tested.

## Baremetal
`target:baremetal` → Multiboot ELF32, entry past header, VGA write + hlt.
