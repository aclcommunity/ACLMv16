#!/usr/bin/env python3
"""QEMU Multiboot run-verify (not build-only)."""
import subprocess, sys, tempfile, os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from aclm.compiler import compile_source, compile_file

QEMU = "/usr/bin/qemu-system-x86_64"
if not os.path.isfile(QEMU):
    print("SKIP: qemu not installed")
    sys.exit(0)

def boot(src=None, path=None, needle=""):
    elf_path = tempfile.mktemp(suffix=".elf")
    ser_path = tempfile.mktemp(suffix=".log")
    if path:
        compile_file(str(path), elf_path)
    else:
        open(elf_path, "wb").write(compile_source(src))
    try:
        subprocess.run(
            [QEMU, "-kernel", elf_path, "-serial", f"file:{ser_path}",
             "-display", "none", "-no-reboot"],
            timeout=2, capture_output=True,
        )
    except subprocess.TimeoutExpired:
        pass
    text = open(ser_path, "rb").read().decode("latin1", errors="replace")
    try:
        os.unlink(elf_path)
        os.unlink(ser_path)
    except Exception:
        pass
    return text

failed = 0

text = boot(src="""target:baremetal
chip:serial_init
data:const m = "BOOTOK\\n"
kernel:printk_str m
chip:cli
chip:halt
""", needle="BOOTOK")
if "BOOTOK" not in text:
    print("FAIL serial:", repr(text)); failed += 1
else:
    print("PASS serial: BOOTOK")

text = boot(src="""target:baremetal
chip:serial_init
kernel:ramfs_init
data:const n = "f.txt"
data:const b = "hi"
data:const ok = "RAMOK\\n"
cpu:set reg2 = b
cpu:set reg3 = 2
kernel:ramfs_put n, reg2, reg3
kernel:ramfs_get reg1 = n
cmp reg1, 0
jump_if eq ~f
kernel:printk_str ok
chip:cli
chip:halt
~f
chip:halt
""")
if "RAMOK" not in text:
    print("FAIL ramfs:", repr(text)); failed += 1
else:
    print("PASS ramfs: RAMOK")

text = boot(src="""target:baremetal
chip:serial_init
kernel:idt_install
data:const m = "IDTOK\\n"
kernel:printk_str m
chip:cli
chip:halt
""")
if "IDTOK" not in text:
    print("FAIL idt:", repr(text)); failed += 1
else:
    print("PASS idt: IDTOK")

lab = ROOT / "labs" / "minios_kernel.aclm"
if lab.exists():
    text = boot(path=lab)
    if "MiniOS" in text and "[ok]" in text:
        print("PASS minios_kernel")
    else:
        print("FAIL minios:", repr(text[:100])); failed += 1

sys.exit(1 if failed else 0)
