# ACLM Kernel / Freestanding Contract (v0.16.0)

## Goal
Language fit for a **small terminal-only OS/kernel** on supported x86 Multiboot,
not a Linux replacement.

## `target:baremetal`

Produces **ELF32 Multiboot1** image:

```text
ELF32 headers
Multiboot1 header (0x1BADB002)
32-bit trampoline:
  cli, stack @ 0x90000
  lgdt
  PAE + CR3 (identity map 0..1GiB, 2MiB pages)
  EFER.LME
  CR0.PG
  far jump → 64-bit CS
64-bit user payload (ACLM codegen)
hlt; jmp $
data
```

- **No** Linux `sys:call` (compile error).
- Entry = first instruction of trampoline (after Multiboot header).

## Tier-1 surface

| Feature | Syntax / notes |
|---------|----------------|
| Long mode | Automatic in baremetal image (`aclm/kernel_boot.py`) |
| Halt / IRQ flag | `chip:cli` `chip:sti` `chip:halt` |
| Ports | `port:in` / `port:out` |
| Serial COM1 | `chip:serial_init` · `chip:serial_putc <byte>` |
| IDT/GDT load | `chip:lidt reg` · `chip:lgdt reg` (reg → IDTR/GDTR memory) |
| Raw escape | `raw:` for custom sequences |

## Still Tier-2+

- Full IDT gate builders / IRQ stubs library
- Page fault handler policy
- Heap/page allocator API
- Context switch / syscalls
- Keyboard shell

## Tests
- `test_340_kernel_no_syscall` — sys:call must fail
- `test_341` / baremetal_* — Multiboot + long-mode image build
- `test_350_serial_baremetal` — serial helpers build
- `test_351_longmode_markers` — EFER constant present in image

## Honest limits
Identity map is **first 1GiB only**. QEMU/GRUB required to *run* the image;
userspace `./kernel.elf` will not execute (Exec format / wrong mode).


## Tier-2 surface (v0.15.2)

| Feature | Syntax |
|---------|--------|
| Bump heap | `kernel:heap_init N` · `kernel:heap_alloc dest = size` |
| Context | `kernel:ctx_save reg` · `kernel:ctx_load reg` (128-byte GPR block) |
| Keyboard poll | `chip:kbd_poll dest` (ports 0x64/0x60) |
| Soft IRQ | `chip:int n` |
| IDT default | `kernel:idt_install` (all vectors → cli;hlt stub, then lidt) |

Still later: full IRQ routing, preemptive scheduler, user rings, FS, net.


## Tier-3 surface (v0.15.3)

| Feature | Syntax |
|---------|--------|
| PIT | `chip:pit_init [divisor]` (default ~100Hz) |
| PIC remap | `chip:pic_remap` (IRQ 0x20/0x28) |
| Coop switch | `kernel:coop_switch save_ctx, load_ctx` |
| Printk | `kernel:printk_str label` (NUL string via serial) |
| Panic | `kernel:panic` (cli, serial 'P', hlt loop) |

See `labs/kernel_tier3_min.aclm`.

Still open: preemptive IRQ-driven schedule, ring3, FS, net.


## Tier-4 surface (v0.15.4)

| Feature | Syntax |
|---------|--------|
| Timer IRQ0 | `kernel:tick_install` · `kernel:tick_read dest` |
| Ramfs (8 slots) | `kernel:ramfs_init` · `ramfs_put name, ptr, len` · `ramfs_get dest = name` |
| Net stub | `kernel:net_init` · `kernel:net_poll dest` (always 0) |
| Privilege probe | `kernel:cs_ring dest` (CS & 3) |

`labs/kernel_tier4_min.aclm` — combined bring-up sketch.

Still later: full ring3 iret path, real NIC driver, preemptive yield-on-IRQ.


## Tier-5 surface (v0.15.5)

| Feature | Syntax |
|---------|--------|
| User segments | GDT now includes DPL3 code/data (selectors **0x1B** / **0x23**) |
| Enter ring3 | `kernel:enter_user entry, stack` (iretq frame) |
| Page-fault gate | `kernel:pf_install` (vector 14 → cli;hlt) |
| Net allowlist | `kernel:net_allow_port n` · `kernel:net_check_port dest = n` |
| Preempt arm | `kernel:preempt_arm ctx_reg` (stores hint for IRQ0) |

**Security note:** default net policy is deny; only allowed ports pass `net_check_port`.

Still not full: hardware NIC DMA, forced preemptive rewrite of all registers on IRQ, syscall MSR (STAR/LSTAR).


## Tier-6 surface (v0.15.6)

| Feature | Syntax |
|---------|--------|
| Syscall MSRs | `kernel:syscall_init` (EFER.SCE, STAR, LSTAR, SFMASK) |
| Sysret | `kernel:sysret` |
| Full IRQ GPR save | `kernel:irq_full_save_on` (IRQ0 saves rax..r15) |
| NIC MMIO | `kernel:nic_bar addr` · `nic_reg_read` · `nic_reg_write` |

LSTAR points at internal `__syscall_entry` (default: immediate `sysret`).
NIC helpers are **BAR-relative MMIO** (identity-mapped phys); wire a real E1000 BAR in your board code.

Still research-grade: multi-queue DMA rings, full syscall ABI table, NMI.


## Tier-7 surface (v0.15.7)

| Feature | Syntax |
|---------|--------|
| Syscall table | `kernel:syscall_table_init` (64 slots → `__nosys`) |
| Register | `kernel:syscall_register nr, ~handler` |
| NMI | `kernel:nmi_install` (IDT[2]) |
| DMA ring | `kernel:dma_ring_init N` · `dma_ring_push addr,len` · `dma_ring_pop a,l` |

`syscall_table_init` also sets LSTAR to `__syscall_dispatch` (rax=nr → call table).
DMA ring: power-of-2 slots, 16-byte descriptors `{addr,u64 len}`; status in **reg1** (0=ok, 1=full/empty).


## Audit fix (v0.15.8) — long-mode + syscall clobber

**Problem (confirmed):** baremetal images triple-faulted after Multiboot because
64-bit entry lacked proper DS/SS setup after CS switch, GDT packing was fragile,
and the test suite was **build-only** (never QEMU-run).

**Fix:**
1. `kernel_boot.py` — after 32-bit `0xEA` far jump into 64-bit CS, a dedicated
   64-bit stub loads DS/ES/SS=0x10, RSP=0x90000, then `jmp kmain`.
2. GDT entries packed as explicit 8-byte descriptors (`HHBBBB`).
3. `sys:call` saves/restores **RCX and R11** (Linux syscall clobbers).

**Still required for green runtime:** QEMU (or real HW) boot tests in CI —
compile-only is not enough. Run:

```bash
qemu-system-x86_64 -kernel calcos_kernel.elf -serial stdio -display none -no-reboot
```

Expect serial output or clean halt; triple-fault = still broken.


## Register note (v0.15.9)

- Virtual **reg10 maps to r11**. Many codegen paths historically used r11 as a temp.
- Critical paths (syscall RCX/R11 save, port:in mask, 32-bit mask) now avoid clobbering user-visible regs via SCRATCH (r15) or push/pop.
- Prefer reg1–reg9 / reg11–reg13 for long-lived values across complex ops if unsure.


## Limits addressed (v0.16.0)

1. **reg10/r11 clobber**
   - `r11` reserved (SECOND_SCRATCH); not a virtual user register.
   - Map: reg1–reg9, reg10=r12, reg11=r13, reg12=r14.
   - `reg13` compat alias → r14 (prefer reg12).

2. **QEMU run-verify**
   - Smoke boots: serial, ramfs, idt, minios_kernel (real serial output).
   - `run_all` fails if QEMU smoke fails when qemu is present.

3. **Shell / disk**
   - ramfs only (no ATA/virtio yet).
   - MiniOS = scripted serial demo, not full interactive TTY.
