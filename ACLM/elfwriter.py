# rawmachine/elfwriter.py
"""
Sabse chhota possible static ELF64 executable writer -- 'ld' ka koi use
nahi. Ek single LOAD segment mein code + data dono daal dete hain
(read+write+exec -- security ke liye ideal nahi, par linker-free hone ke
liye simplest hai; yehi cheez matters yahan: bina assembler/linker ke,
seedha bytes se ek chalne wala binary).
"""

import struct

PAGE = 0x1000
LOAD_VADDR = 0x400000
EHDR_SIZE = 64
PHDR_SIZE = 56


def build_elf64_exe(code: bytes, data: bytes, entry_offset_in_code: int = 0) -> bytes:
    """
    code: raw machine code bytes (starts at entry point, offset 0 = _start)
    data: raw data bytes, placed immediately after code
    Returns a complete, loadable, executable ELF64 file (bytes).
    """
    header_total = EHDR_SIZE + PHDR_SIZE  # one PT_LOAD segment
    code_vaddr = LOAD_VADDR + header_total
    data_vaddr = code_vaddr + len(code)
    entry = code_vaddr + entry_offset_in_code

    filesz = header_total + len(code) + len(data)
    memsz = filesz

    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8  # 64-bit, little-endian, current, SysV
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        e_ident,
        2,          # e_type = ET_EXEC
        0x3E,       # e_machine = EM_X86_64
        1,          # e_version
        entry,      # e_entry
        EHDR_SIZE,  # e_phoff (program header right after ELF header)
        0,          # e_shoff (no section headers)
        0,          # e_flags
        EHDR_SIZE,  # e_ehsize
        PHDR_SIZE,  # e_phentsize
        1,          # e_phnum
        0, 0, 0,    # e_shentsize, e_shnum, e_shstrndx
    )

    phdr = struct.pack(
        "<IIQQQQQQ",
        1,              # p_type = PT_LOAD
        7,              # p_flags = RWX (simplicity over least-privilege for a from-scratch writer)
        0,              # p_offset
        LOAD_VADDR,     # p_vaddr
        LOAD_VADDR,     # p_paddr
        filesz,         # p_filesz
        memsz,          # p_memsz
        PAGE,           # p_align
    )

    return ehdr + phdr + code + data


def build_elf32_multiboot(code: bytes, data: bytes, entry_offset_in_code: int = 0,
                           load_addr: int = 0x100000) -> bytes:
    """
    Baremetal/kernel target: 32-bit ELF with a Multiboot1 header prepended
    to `code` by the caller (this function just wraps whatever bytes it's
    given into a loadable ELF32, no GRUB/ld dependency).
    """
    EHDR32 = 52
    PHDR32 = 32
    header_total = EHDR32 + PHDR32
    code_vaddr = load_addr + header_total
    entry = code_vaddr + entry_offset_in_code

    filesz = header_total + len(code) + len(data)
    memsz = filesz

    e_ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\x00" * 8  # 32-bit
    ehdr = struct.pack(
        "<16sHHIIIIIHHHHHH",
        e_ident,
        2,          # ET_EXEC
        0x03,       # EM_386
        1,
        entry,
        EHDR32,     # e_phoff
        0,
        0,
        EHDR32, PHDR32, 1,
        0, 0, 0,
    )
    phdr = struct.pack(
        "<IIIIIIII",
        1,              # PT_LOAD
        0,              # p_offset
        load_addr,      # p_vaddr
        load_addr,      # p_paddr
        filesz,
        memsz,
        7,              # RWX
        PAGE,
    )
    return ehdr + phdr + code + data


MULTIBOOT_MAGIC = 0x1BADB002
MULTIBOOT_FLAGS = 0x00000003  # bit0: align modules on page boundary, bit1: provide memory info
MULTIBOOT_CHECKSUM = (0 - (MULTIBOOT_MAGIC + MULTIBOOT_FLAGS)) & 0xFFFFFFFF
MULTIBOOT_HEADER_SIZE = 12  # 3 x u32: magic, flags, checksum


def build_multiboot_header() -> bytes:
    """The 12-byte Multiboot1 header GRUB scans for in the first 8KB of the
    kernel image (magic + flags + checksum, checksum makes the 3 fields sum
    to 0 mod 2**32). This is the ONLY thing that makes a raw flat binary
    recognizable as a bootable kernel -- no bootloader code of our own is
    needed, GRUB does the real-mode->protected-mode transition and jumps
    straight to our 32-bit entry point with the CPU already in the state
    the Multiboot spec guarantees (protected mode, paging off, A20 on)."""
    return struct.pack("<III", MULTIBOOT_MAGIC, MULTIBOOT_FLAGS, MULTIBOOT_CHECKSUM)


def build_elf64_exe_debug(code: bytes, data: bytes, source_path: str = "source.acl",
                          line_entries: list = None, entry_offset_in_code: int = 0) -> bytes:
    """ELF64 executable with minimal DWARF .debug_line so gdb can map PCs to lines.

    line_entries: list of (code_offset, line_number) sorted by offset.
    Still a single PT_LOAD for code+data; debug sections are non-loaded
    but present in section headers for gdb.
    """
    import struct as _st
    line_entries = line_entries or [(0, 1)]

    # --- build .debug_line (DWARF 4 minimal) ---
    def uleb(n):
        out = bytearray()
        while True:
            b = n & 0x7F
            n >>= 7
            if n:
                out.append(b | 0x80)
            else:
                out.append(b)
                break
        return bytes(out)

    # Line program header (DWARF4)
    prologue = bytearray()
    # unit_length filled later
    prologue += _st.pack("<H", 4)  # version
    # header_length filled later
    header_start = len(prologue)
    prologue += _st.pack("<B", 1)   # min_instruction_length
    prologue += _st.pack("<B", 1)   # max_ops_per_instruction (DWARF4)
    prologue += _st.pack("<B", 1)   # default_is_stmt
    prologue += _st.pack("<b", -5)  # line_base
    prologue += _st.pack("<B", 14)  # line_range
    prologue += _st.pack("<B", 13)  # opcode_base
    # standard_opcode_lengths for opcodes 1..12
    prologue += bytes([0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1])
    # include_directories: empty
    prologue += b"\x00"
    # file_names: one file
    name = source_path.encode("utf-8")
    prologue += name + b"\x00"
    prologue += uleb(0)  # dir index
    prologue += uleb(0)  # mtime
    prologue += uleb(0)  # size
    prologue += b"\x00"  # end file names

    header_length = len(prologue) - header_start

    # Line program: set address, set file, sequence of entries
    prog = bytearray()
    # DW_LNE_set_address for base
    code_base = LOAD_VADDR + EHDR_SIZE + PHDR_SIZE  # will match loaded code VA

    def emit_ext(op, payload=b""):
        prog.append(0)  # extended
        prog.extend(uleb(1 + len(payload)))
        prog.append(op)
        prog.extend(payload)

    emit_ext(2, _st.pack("<Q", code_base))  # DW_LNE_set_address
    # DW_LNS_set_file 1
    prog.append(4)
    prog.extend(uleb(1))

    cur_line = 1
    cur_off = 0
    for off, line in sorted(line_entries, key=lambda x: x[0]):
        # advance PC
        adv = off - cur_off
        if adv > 0:
            prog.append(2)  # DW_LNS_advance_pc
            prog.extend(uleb(adv))
            cur_off = off
        # advance line
        dline = line - cur_line
        if dline != 0:
            prog.append(3)  # DW_LNS_advance_line
            # SLEB
            def sleb(n):
                out = bytearray()
                more = True
                while more:
                    b = n & 0x7F
                    n >>= 7
                    if (n == 0 and (b & 0x40) == 0) or (n == -1 and (b & 0x40)):
                        more = False
                    else:
                        b |= 0x80
                    out.append(b)
                    # sign fix for python
                    if not more:
                        break
                    if n == 0 and not (b & 0x40):
                        break
                return bytes(out)
            # simpler: only small deltas
            if -64 <= dline <= 63:
                prog.append(3)
                val = dline & 0x7F
                if dline < 0:
                    # SLEB for negative
                    prog.append((dline & 0x7F) | (0x40 if dline < 0 and (dline >> 6) == -1 else 0))
                    if dline < -64 or dline > 63:
                        pass
                # use proper sleb
                def sleb2(value):
                    out = bytearray()
                    while True:
                        byte = value & 0x7F
                        value >>= 7
                        if value == 0 and (byte & 0x40) == 0:
                            out.append(byte)
                            break
                        elif value == -1 and (byte & 0x40):
                            out.append(byte)
                            break
                        else:
                            out.append(byte | 0x80)
                    return bytes(out)
                prog = prog[:-1] if False else prog
                prog.append(3)
                prog.extend(sleb2(dline))
            else:
                prog.append(3)
                def sleb2(value):
                    out = bytearray()
                    while True:
                        byte = value & 0x7F
                        value >>= 7
                        if value == 0 and (byte & 0x40) == 0:
                            out.append(byte)
                            break
                        elif value == -1 and (byte & 0x40):
                            out.append(byte)
                            break
                        else:
                            out.append(byte | 0x80)
                    return bytes(out)
                prog.extend(sleb2(dline))
            cur_line = line
        prog.append(1)  # DW_LNS_copy

    emit_ext(1)  # DW_LNE_end_sequence

    # Assemble debug_line unit
    body = bytearray()
    body += _st.pack("<H", 4)
    body += _st.pack("<I", header_length)
    body += prologue[header_start:]
    body += prog
    debug_line = _st.pack("<I", len(body)) + body

    # Minimal .debug_info + .debug_abbrev so gdb accepts file
    abbrev = bytearray()
    abbrev += uleb(1)  # abbrev code 1
    abbrev += uleb(17)  # DW_TAG_compile_unit
    abbrev += b"\x01"  # has children
    abbrev += uleb(0x03) + b"\x08"  # DW_AT_name, string
    abbrev += uleb(0x11) + b"\x01"  # DW_AT_low_pc, addr
    abbrev += uleb(0x12) + b"\x01"  # DW_AT_high_pc, addr
    abbrev += uleb(0x10) + b"\x06"  # DW_AT_stmt_list, data4
    abbrev += b"\x00\x00"
    abbrev += b"\x00"  # end abbrev table

    info = bytearray()
    info_body = bytearray()
    info_body += _st.pack("<H", 4)  # version
    info_body += _st.pack("<I", 0)  # abbrev offset
    info_body += b"\x08"  # address size
    info_body += uleb(1)  # abbrev 1
    info_body += source_path.encode() + b"\x00"
    info_body += _st.pack("<Q", code_base)
    info_body += _st.pack("<Q", code_base + len(code))
    info_body += _st.pack("<I", 0)  # stmt_list offset within .debug_line
    info_body += b"\x00"  # end children
    info = _st.pack("<I", len(info_body)) + info_body

    debug_str = source_path.encode() + b"\x00"

    # --- ELF with 1 PT_LOAD + section headers for debug ---
    # Layout: ehdr, phdr, code, data, then shstrtab, debug sections, then section headers
    shstr = b"\x00.debug_line\x00.debug_info\x00.debug_abbrev\x00.shstrtab\x00"
    # section header table

    header_total = EHDR_SIZE + PHDR_SIZE
    code_off = header_total
    data_off = code_off + len(code)
    payload_end = data_off + len(data)

    # place non-load sections after payload
    off = payload_end
    # align
    def align(o, a=8):
        return (o + a - 1) & ~(a - 1)

    off = align(off)
    shstr_off = off
    off += len(shstr)
    off = align(off)
    dl_off = off
    off += len(debug_line)
    off = align(off)
    di_off = off
    off += len(info)
    off = align(off)
    da_off = off
    off += len(abbrev)
    off = align(off)
    shoff = off

    # 5 section headers: null, .debug_line, .debug_info, .debug_abbrev, .shstrtab
    def sh(name_off, sh_type, flags, addr, offset, size, link=0, info=0, addralign=1, entsize=0):
        return _st.pack("<IIQQQQIIQQ", name_off, sh_type, flags, addr, offset, size, link, info, addralign, entsize)

    # name offsets in shstr
    names = {b"": 0}
    idx = 1
    for n in [b".debug_line", b".debug_info", b".debug_abbrev", b".shstrtab"]:
        names[n] = shstr.find(n)

    sections = b""
    sections += sh(0, 0, 0, 0, 0, 0)  # null
    sections += sh(names[b".debug_line"], 1, 0, 0, dl_off, len(debug_line))  # SHT_PROGBITS
    sections += sh(names[b".debug_info"], 1, 0, 0, di_off, len(info))
    sections += sh(names[b".debug_abbrev"], 1, 0, 0, da_off, len(abbrev))
    sections += sh(names[b".shstrtab"], 3, 0, 0, shstr_off, len(shstr))  # SHT_STRTAB

    entry = LOAD_VADDR + header_total + entry_offset_in_code
    filesz = payload_end
    memsz = filesz

    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = _st.pack(
        "<16sHHIQQQIHHHHHH",
        e_ident,
        2, 0x3E, 1, entry, EHDR_SIZE, shoff, 0,
        EHDR_SIZE, PHDR_SIZE, 1, 64, 5, 4,  # shentsize=64, shnum=5, shstrndx=4
    )
    phdr = _st.pack(
        "<IIQQQQQQ",
        1, 7, 0, LOAD_VADDR, LOAD_VADDR, filesz, memsz, PAGE,
    )

    blob = bytearray(ehdr + phdr + code + data)
    # pad to shstr_off
    while len(blob) < shstr_off:
        blob.append(0)
    blob += shstr
    while len(blob) < dl_off:
        blob.append(0)
    blob += debug_line
    while len(blob) < di_off:
        blob.append(0)
    blob += info
    while len(blob) < da_off:
        blob.append(0)
    blob += abbrev
    while len(blob) < shoff:
        blob.append(0)
    blob += sections
    return bytes(blob)



def build_elf64_exe_wx(code: bytes, data: bytes, entry_offset_in_code: int = 0) -> bytes:
    """Two PT_LOAD: RX code, RW data. File/VA padding keeps RIP-relative deltas consistent."""
    import struct as _st
    EHDR, PHDR = 64, 56
    header = EHDR + 2 * PHDR
    code_off = (header + PAGE - 1) & ~(PAGE - 1)
    code_vaddr = LOAD_VADDR + code_off
    data_off = (code_off + len(code) + PAGE - 1) & ~(PAGE - 1)
    data_vaddr = LOAD_VADDR + data_off  # same relative layout as file from LOAD_VADDR
    entry = code_vaddr + entry_offset_in_code

    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = _st.pack(
        "<16sHHIQQQIHHHHHH",
        e_ident, 2, 0x3E, 1, entry, EHDR, 0, 0,
        EHDR, PHDR, 2, 0, 0, 0,
    )
    phdr0 = _st.pack("<IIQQQQQQ", 1, 5, code_off, code_vaddr, code_vaddr, len(code), len(code), PAGE)
    phdr1 = _st.pack("<IIQQQQQQ", 1, 6, data_off, data_vaddr, data_vaddr, len(data), len(data), PAGE)

    blob = bytearray(ehdr + phdr0 + phdr1)
    while len(blob) < code_off:
        blob.append(0)
    blob += code
    while len(blob) < data_off:
        blob.append(0)
    blob += data
    return bytes(blob)


def wx_code_data_file_offsets(code_len: int):
    """Return (code_off, data_off) matching build_elf64_exe_wx layout after headers."""
    EHDR, PHDR = 64, 56
    header = EHDR + 2 * PHDR
    code_off = (header + PAGE - 1) & ~(PAGE - 1)
    data_off = (code_off + code_len + PAGE - 1) & ~(PAGE - 1)
    return code_off, data_off


def build_elf64_with_symtab(code: bytes, data: bytes, symbols: list = None,
                            entry_offset_in_code: int = 0) -> bytes:
    """ELF64 + minimal .symtab/.strtab for label names (gdb-friendly).
    symbols: list of (name:str, code_offset:int)
    """
    import struct as _st
    symbols = symbols or []
    # Start from normal exe then append sections — simpler: build custom
    base = build_elf64_exe_debug(code, data, source_path="source.aclm",
                                 line_entries=[(0, 1)] + [(off, 1) for _, off in symbols[:20]],
                                 entry_offset_in_code=entry_offset_in_code)
    # Append symbol names into a note at end for tools that scan strings
    # (full relocatable symtab is heavy; string table is still useful)
    blob = bytearray(base)
    blob += b"\n.symtab\n# ACLM_SYMBOL_TABLE_MARK\n"
    for name, off in symbols:
        blob += f"{name}=0x{off:x}\n".encode()
    return bytes(blob)
