# ACLM depth notes v0.11

## mmap
cell:map dest = size [, prot [, flags]]
Defaults: prot=3 (RW), flags=0x22 (PRIVATE|ANON)

## mprotect
cell:protect ptr, size, prot

## signals
sig:action signo, handler
- handler numeric: 0=DFL 1=IGN or address
- handler ~label: address of label (best-effort; no full SA_RESTORER trampoline)
sig:return → rt_sigreturn

## Still limited
- Full SA_RESTORER / sigreturn trampoline for custom handlers
- QEMU live boot depends on host qemu package
- Full gdb .symtab ELF section (map file is text dump)
