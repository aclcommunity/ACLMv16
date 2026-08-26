"""Multiboot1 → long mode. Page tables at PAGE-ALIGNED physical addresses."""

from __future__ import annotations
import struct
from .elfwriter import build_multiboot_header, build_elf32_multiboot

LOAD_ADDR = 0x100000
HEADER_TOTAL = 52 + 32  # 84


def _u32(v: int) -> bytes:
    return struct.pack("<I", v & 0xFFFFFFFF)


def _align(n: int, a: int = 4096) -> int:
    return (n + a - 1) & ~(a - 1)


def build_gdt() -> bytes:
    null = bytes(8)
    # limit=0xfffff, G=1, L=1 for code: classic long-mode code segment
    # bytes: limit0-1, base0-1, base2, access, flags|lim, base3
    code64 = struct.pack("<HHBBBB", 0xFFFF, 0x0000, 0x00, 0x9A, 0xA0, 0x00)  # L=1,G=1
    data = struct.pack("<HHBBBB", 0xFFFF, 0x0000, 0x00, 0x92, 0xC0, 0x00)   # 32-bit data OK
    ucode = struct.pack("<HHBBBB", 0xFFFF, 0x0000, 0x00, 0xFA, 0xA0, 0x00)
    udata = struct.pack("<HHBBBB", 0xFFFF, 0x0000, 0x00, 0xF2, 0xC0, 0x00)
    return null + code64 + data + ucode + udata


def patch_page_tables(blob: bytearray, pml4_phys: int, pdpt_phys: int, pd_phys: int) -> None:
    struct.pack_into("<Q", blob, 0, (pdpt_phys & ~0xFFF) | 0x03)
    struct.pack_into("<Q", blob, 4096, (pd_phys & ~0xFFF) | 0x03)
    for i in range(512):
        struct.pack_into("<Q", blob, 8192 + i * 8, (i * 0x200000) | 0x83)


def build_trampoline32(pml4_phys: int, gdtr_phys: int, long_stub_phys: int) -> bytes:
    code = bytearray()
    def emit(*parts):
        for b in parts:
            if isinstance(b, int):
                code.append(b & 0xFF)
            else:
                code.extend(b)
    emit(0xFA)
    emit(0xBC, _u32(0x90000))
    emit(0xB8, _u32(gdtr_phys))
    emit(0x0F, 0x01, 0x10)              # lgdt [eax]
    emit(0x0F, 0x20, 0xE0)
    emit(0x83, 0xC8, 0x20)
    emit(0x0F, 0x22, 0xE0)              # cr4 PAE
    emit(0xB8, _u32(pml4_phys))
    emit(0x0F, 0x22, 0xD8)              # cr3
    emit(0xB9, _u32(0xC0000080))
    emit(0x0F, 0x32)
    emit(0x0D, _u32(0x100))
    emit(0x0F, 0x30)                    # EFER.LME
    emit(0x0F, 0x20, 0xC0)
    emit(0x0D, _u32(0x80000001))
    emit(0x0F, 0x22, 0xC0)              # CR0.PG|PE
    emit(0xEA, _u32(long_stub_phys), struct.pack("<H", 0x0008))
    return bytes(code)


def build_long_mode_stub64(kmain_phys: int) -> bytes:
    code = bytearray()
    def emit(*parts):
        for b in parts:
            if isinstance(b, int):
                code.append(b & 0xFF)
            else:
                code.extend(b)
    emit(0x66, 0xB8, 0x10, 0x00)        # mov ax, 0x10
    emit(0x8E, 0xD8)                    # mov ds, ax
    emit(0x8E, 0xC0)                    # mov es, ax
    emit(0x8E, 0xD0)                    # mov ss, ax
    emit(0x48, 0xBC, *struct.pack("<Q", 0x90000))  # mov rsp, 0x90000
    emit(0x48, 0xB8, *struct.pack("<Q", kmain_phys))
    emit(0xFF, 0xE0)                    # jmp rax
    return bytes(code)


def build_long_mode_kernel(user64: bytes, data_b: bytes, load_addr: int = LOAD_ADDR) -> bytes:
    mb = build_multiboot_header()
    gdt = build_gdt()
    dummy = build_trampoline32(0x2000, 0x3000, 0x100000)
    tlen = len(dummy)
    stub = build_long_mode_stub64(0x100000)
    stub_len = len(stub)

    code_start = load_addr + HEADER_TOTAL  # 0x100054 typically

    off = len(mb) + tlen
    # Align so PHYSICAL address of PML4 is page-aligned
    # phys = code_start + off; need phys % 4096 == 0
    while (code_start + off) % 4096 != 0:
        off += 1
    pml4_off = off
    off += 4096
    pdpt_off = off
    off += 4096
    pd_off = off
    off += 4096
    # GDTR + GDT
    gdtr_off = off
    off += 6
    while (code_start + off) % 8 != 0:
        off += 1
    gdt_off = off
    off += len(gdt)
    while (code_start + off) % 16 != 0:
        off += 1
    stub_off = off
    off += stub_len
    while (code_start + off) % 16 != 0:
        off += 1
    user_off = off

    pml4_phys = code_start + pml4_off
    pdpt_phys = code_start + pdpt_off
    pd_phys = code_start + pd_off
    gdt_phys = code_start + gdt_off
    gdtr_phys = code_start + gdtr_off
    stub_phys = code_start + stub_off
    kmain_phys = code_start + user_off

    assert pml4_phys % 4096 == 0, hex(pml4_phys)
    assert pdpt_phys % 4096 == 0
    assert pd_phys % 4096 == 0

    tramp = build_trampoline32(pml4_phys, gdtr_phys, stub_phys)
    assert len(tramp) == tlen
    stub = build_long_mode_stub64(kmain_phys)

    pages = bytearray(4096 * 3)
    patch_page_tables(pages, pml4_phys, pdpt_phys, pd_phys)
    gdtr6 = struct.pack("<HI", len(gdt) - 1, gdt_phys & 0xFFFFFFFF)

    blob = bytearray()
    blob.extend(mb)
    blob.extend(tramp)
    while len(blob) < pml4_off:
        blob.append(0)
    blob.extend(pages)
    while len(blob) < gdtr_off:
        blob.append(0)
    blob.extend(gdtr6)
    while len(blob) < gdt_off:
        blob.append(0)
    blob.extend(gdt)
    while len(blob) < stub_off:
        blob.append(0x90)
    blob.extend(stub)
    while len(blob) < user_off:
        blob.append(0x90)
    blob.extend(user64)
    # CRITICAL: data must sit immediately after user64 so RIP-relative
    # lea [rip+disp] labels (linked as offset code_len+...) resolve correctly.
    blob.extend(data_b)
    blob.extend(bytes([0xF4, 0xEB, 0xFE]))

    return build_elf32_multiboot(bytes(blob), b"", entry_offset_in_code=len(mb), load_addr=load_addr)

