#!/usr/bin/env python3
"""Builds small ELF and PE files, valid and deliberately broken, for test_headers.sh.

Usage: make_headers_fixtures.py DIRECTORY

The files only have headers and filler bytes. None of them is a working program, so
they are harmless. Everything is written byte by byte, so the expected results are
known exactly and no compiler for Linux or Windows is needed.
"""

import random
import struct
import sys
from pathlib import Path

UNIFORM = bytes(range(256)) * 4  # 1024 bytes with an entropy of exactly 8


# ---- PE --------------------------------------------------------------------------

LFANEW = 0x80
COFF = LFANEW + 4
OPTIONAL = COFF + 20
IDATA_RVA = 0x2000
IDATA_OFFSET = 0x600


def build_idata(plus):
    dlls = [
        ("KERNEL32.dll", True, ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread",
                                "IsDebuggerPresent", "GetLastError"]),
        ("urlmon.dll", False, ["URLDownloadToFileA"]),  # no original list: use the other one
        ("WS2_32.dll", True, [115]),                    # imported by number
    ]
    pack = "<Q" if plus else "<I"
    ordinal_flag = 1 << 63 if plus else 1 << 31
    data = bytearray(20 * (len(dlls) + 1))

    def alloc(blob):
        rva = IDATA_RVA + len(data)
        data.extend(blob)
        return rva

    for i, (name, has_original, functions) in enumerate(dlls):
        name_rva = alloc(name.encode() + b"\0")
        entries = []
        for function in functions:
            if isinstance(function, int):
                entries.append(ordinal_flag | function)
            else:
                entries.append(alloc(b"\0\0" + function.encode() + b"\0"))
        thunks = alloc(b"".join(struct.pack(pack, e) for e in entries + [0]))
        struct.pack_into("<IIIII", data, i * 20, thunks if has_original else 0, 0, 0, name_rva, thunks)
    return bytes(data)


def build_pe(plus=True):
    optional_size = 240 if plus else 224
    table = OPTIONAL + optional_size
    idata = build_idata(plus)
    image = bytearray(0xE00)

    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, LFANEW)
    image[LFANEW:LFANEW + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", image, COFF, 0x8664 if plus else 0x14C, 3, 0, 0, 0, optional_size, 0x22)

    struct.pack_into("<H", image, OPTIONAL, 0x20B if plus else 0x10B)
    struct.pack_into("<I", image, OPTIONAL + 16, 0x1234)
    struct.pack_into("<I", image, OPTIONAL + (108 if plus else 92), 16)
    directories = OPTIONAL + (112 if plus else 96)
    struct.pack_into("<II", image, directories + 8, IDATA_RVA, len(idata))

    sections = [
        (b".text", 0x200, 0x1000, 0x200, 0x400, 0x60000020),
        (b".idata", 0x400, IDATA_RVA, 0x400, IDATA_OFFSET, 0xC0000040),
        (b".evil\x1b[", 0x400, 0x3000, 0x400, 0xA00, 0xE0000020),
    ]
    for i, (name, vsize, rva, raw, offset, flags) in enumerate(sections):
        at = table + i * 40
        image[at:at + 8] = name.ljust(8, b"\0")
        struct.pack_into("<IIII", image, at + 8, vsize, rva, raw, offset)
        struct.pack_into("<I", image, at + 36, flags)

    image[0x400:0x600] = b"\x90" * 0x200
    image[IDATA_OFFSET:IDATA_OFFSET + len(idata)] = idata
    image[0xA00:0xE00] = UNIFORM
    return bytes(image)


# ---- ELF -------------------------------------------------------------------------

def build_elf(is_64=True, big=False):
    e = ">" if big else "<"
    header_size = 64 if is_64 else 52
    symbol_size = 24 if is_64 else 16

    dynstr = b"\0ptrace\0execve\0my_export\0"

    def symbol(name, section_index):
        if is_64:
            return struct.pack(e + "IBBHQQ", name, 0x12, 0, section_index, 0, 0)
        return struct.pack(e + "IIIBBH", name, 0, 0, 0x12, 0, section_index)

    dynsym = symbol(0, 0) + symbol(1, 0) + symbol(8, 0) + symbol(15, 1)

    names = [b"", b".text", b".evil", b".bss", b".dynsym", b".dynstr", b".shstrtab"]
    shstrtab = b""
    name_offsets = []
    for name in names:
        name_offsets.append(len(shstrtab))
        shstrtab += name + b"\0"

    # (type, flags, content, link, memory-only size)
    sections = [
        (0, 0, b"", 0, 0),
        (1, 2 | 4, b"\x90" * 0x200, 0, 0),
        (1, 1 | 2 | 4, UNIFORM, 0, 0),
        (8, 1 | 2, b"", 0, 0x1000),
        (11, 2, dynsym, 5, 0),
        (3, 2, dynstr, 0, 0),
        (3, 0, shstrtab, 0, 0),
    ]

    body = bytearray(header_size)
    placed = []
    for _, _, content, _, _ in sections:
        placed.append(len(body))
        body.extend(content)
    while len(body) % 8:
        body.append(0)
    table = len(body)

    for i, (kind, flags, content, link, memory) in enumerate(sections):
        size = memory if kind == 8 else len(content)
        if is_64:
            body.extend(struct.pack(e + "IIQQQQIIQQ", name_offsets[i], kind, flags, 0x1000 * i,
                                    placed[i], size, link, 0, 1, symbol_size if kind == 11 else 0))
        else:
            body.extend(struct.pack(e + "IIIIIIIIII", name_offsets[i], kind, flags, 0x1000 * i,
                                    placed[i], size, link, 0, 1, symbol_size if kind == 11 else 0))

    ident = b"\x7fELF" + bytes([2 if is_64 else 1, 2 if big else 1, 1]) + b"\0" * 9
    machine = 62 if is_64 else 8
    if is_64:
        header = struct.pack(e + "HHIQQQIHHHHHH", 3, machine, 1, 0x1040, 0, table, 0,
                             64, 0, 0, 64, len(sections), 6)
    else:
        header = struct.pack(e + "HHIIIIIHHHHHH", 2, machine, 1, 0x1040, 0, table, 0,
                             52, 0, 0, 40, len(sections), 6)
    body[0:header_size] = ident + header
    return bytes(body)


def patch(data, offset, blob):
    out = bytearray(data)
    out[offset:offset + len(blob)] = blob
    return bytes(out)


def overlapping_sections(pe, table):
    """Many sections that all claim the whole file, to make us measure it again and again."""
    count = 16
    out = patch(pe, COFF + 2, struct.pack("<H", count))
    for i in range(count):
        out = patch(out, table + i * 40 + 16, struct.pack("<II", len(pe), 0))
    return out


def main():
    out = Path(sys.argv[1])
    pe = build_pe()
    elf = build_elf()

    valid = {
        "valid-pe64.exe": pe,
        "valid-pe32.exe": build_pe(plus=False),
        "valid-elf64": elf,
        "valid-elf32-big": build_elf(is_64=False, big=True),
    }

    table = OPTIONAL + 240
    import_directory = OPTIONAL + 112 + 8
    shoff_at = 40
    table_elf = struct.unpack_from("<Q", elf, shoff_at)[0]

    broken = {
        # PE
        "pe-lfanew-outside": patch(pe, 0x3C, b"\xf0\xff\xff\xff"),
        "pe-no-signature": patch(pe, LFANEW, b"XXXX"),
        "pe-cut-in-coff": pe[:COFF + 6],
        "pe-bad-magic": patch(pe, OPTIONAL, b"\x99\x99"),
        "pe-cut-in-sections": pe[:table + 50],
        "pe-many-sections": patch(pe, COFF + 2, b"\xff\xff") + bytes(0x4000),  # table fits in the file
        "pe-sections-past-end": patch(pe, COFF + 2, b"\xff\xff"),
        "pe-section-outside": patch(pe, table + 2 * 40 + 20, b"\xff\xff\xff\x7f"),
        "pe-import-rva-outside": patch(pe, import_directory, b"\x00\x00\xff\x7f"),
        "pe-cut-in-imports": pe[:IDATA_OFFSET + 30],
        "pe-cut-in-name": pe[:IDATA_OFFSET + 0x90],
        "pe-no-terminator": patch(pe, IDATA_OFFSET + 60, b"A" * 0x3a0),
        "pe-self-loop": patch(pe, IDATA_OFFSET, struct.pack("<I", IDATA_RVA)),
        "pe-overlapping": overlapping_sections(pe, table),
        # ELF
        "elf-bad-class": patch(elf, 4, b"\x07"),
        "elf-bad-encoding": patch(elf, 5, b"\x07"),
        "elf-cut-in-header": elf[:30],
        "elf-table-outside": patch(elf, shoff_at, struct.pack("<Q", 0xFFFFFFFFFFFF0000)),
        "elf-no-table": patch(elf, shoff_at, struct.pack("<Q", 0)),
        "elf-entry-size-small": patch(elf, 58, struct.pack("<H", 8)),
        "elf-many-sections": patch(elf, 60, struct.pack("<H", 0xFFFF)),
        "elf-bad-names-index": patch(elf, 62, struct.pack("<H", 0x7777)),
        "elf-cut-in-table": elf[:table_elf + 100],
        "elf-section-outside": patch(elf, table_elf + 2 * 64 + 24, struct.pack("<Q", 0xFFFFFFFFFFFFFF00)),
        "elf-symbols-outside": patch(elf, table_elf + 4 * 64 + 24, struct.pack("<Q", 0xFFFFFFFFFFFFFF00)),
        "elf-symbols-huge": patch(elf, table_elf + 4 * 64 + 32, struct.pack("<Q", 0xFFFFFFFFFFFFFF00)),
        "elf-bad-symbol-link": patch(elf, table_elf + 4 * 64 + 40, struct.pack("<I", 0x7777)),
        "elf-strings-outside": patch(elf, table_elf + 5 * 64 + 24, struct.pack("<Q", 0xFFFFFFFFFFFFFF00)),
    }

    for name, data in {**valid, **broken}.items():
        (out / name).write_bytes(data)

    # Random damage. The seed is fixed so that a failure can be reproduced.
    rng = random.Random(1337)
    fuzz = out / "fuzz"
    fuzz.mkdir()
    for index in range(150):
        base = bytearray(rng.choice(list(valid.values())))
        if index % 3 == 0:
            del base[rng.randrange(len(base)):]
        else:
            for _ in range(rng.randint(1, 24)):
                # Most of the interesting fields live in the first part of the file
                limit = len(base) if rng.random() < 0.3 else min(0x400, len(base))
                base[rng.randrange(limit)] = rng.choice([0, 0xFF, 0x7F, 0x80, rng.randrange(256)])
        (fuzz / f"case-{index:03d}").write_bytes(base)


if __name__ == "__main__":
    main()
