// Reads the headers of an ELF file, the executable format of Linux.
//
// The layout: a fixed header at the start points to a table of section headers, each
// describing one part of the file. Imported functions are listed in the .dynsym section
// as symbols marked "undefined", meaning that they live in some other library.
//
// The same structures exist in 32 and 64 bits with different field positions, and in
// little and big endian. That is why the offsets below are written out by hand and the
// file is not simply cast to a struct: casting would depend on this machine's layout
// and endianness, and would read out of bounds on a truncated file.

#include "binary.h"

#include <stdio.h>

enum
{
    ELF_CLASS_32 = 1,
    ELF_CLASS_64 = 2,
    ELF_DATA_BIG = 2,
    ELF_DATA_LITTLE = 1,
    SECTION_NULL = 0,
    SECTION_NOBITS = 8,    // takes memory but no space in the file, like .bss
    SECTION_DYNSYM = 11,
    FLAG_WRITE = 1,
    FLAG_ALLOC = 2,
    FLAG_EXEC = 4,
    SYMBOL_UNDEFINED = 0,
};

typedef struct
{
    uint32_t name;
    uint32_t type;
    uint64_t flags;
    uint64_t addr;
    uint64_t offset;
    uint64_t size;
    uint32_t link;
} SectionHeader;

static const char *machine_name(unsigned machine)
{
    switch (machine)
    {
        case 3:    return "x86";
        case 8:    return "MIPS";
        case 40:   return "ARM";
        case 62:   return "x86-64";
        case 183:  return "AArch64";
        case 243:  return "RISC-V";
        default:   return "unknown machine";
    }
}

static const char *type_name(unsigned type)
{
    switch (type)
    {
        case 1:    return "relocatable object";
        case 2:    return "executable";
        case 3:    return "shared object or PIE";
        case 4:    return "core dump";
        default:   return "unknown type";
    }
}

// A field that is 4 bytes in ELF32 and 8 bytes in ELF64
static uint64_t read_word(Reader *r, uint64_t offset, int is_64)
{
    return is_64 ? reader_u64(r, offset) : reader_u32(r, offset);
}

static SectionHeader read_section_header(Reader *r, uint64_t at, int is_64)
{
    SectionHeader h;
    h.name = reader_u32(r, at);
    h.type = reader_u32(r, at + 4);
    h.flags = read_word(r, at + 8, is_64);
    h.addr = read_word(r, at + (is_64 ? 16 : 12), is_64);
    h.offset = read_word(r, at + (is_64 ? 24 : 16), is_64);
    h.size = read_word(r, at + (is_64 ? 32 : 20), is_64);
    h.link = reader_u32(r, at + (is_64 ? 40 : 24));
    return h;
}

// Lists the undefined symbols of a .dynsym section. `strings` is the section holding
// the names, which sh_link points to.
static void read_imports(Binary *b, Reader *r, SectionHeader symbols, SectionHeader strings, int is_64)
{
    uint64_t entry_size = is_64 ? 24 : 16;

    if (symbols.offset >= r->size)
    {
        binary_warn(b, "import table is damaged");
        return;
    }

    // Never loop further than the file can actually hold, whatever the header claims
    uint64_t count = symbols.size;
    if (r->size - symbols.offset < count)
    {
        binary_warn(b, "import table is damaged");
        count = r->size - symbols.offset;
    }
    count /= entry_size;

    for (uint64_t i = 1; i < count; i++)   // entry 0 is always an empty one
    {
        uint64_t at = symbols.offset + i * entry_size;
        uint32_t name = reader_u32(r, at);
        unsigned section_index = reader_u16(r, at + (is_64 ? 6 : 14));

        if (r->failed)
        {
            r->failed = 0;
            binary_warn(b, "import table is damaged");
            return;
        }
        if (section_index != SYMBOL_UNDEFINED || name == 0)
        {
            continue;
        }

        const char *text = name < strings.size ? reader_string(r, strings.offset + name) : NULL;
        if (text == NULL)
        {
            r->failed = 0;
            binary_warn(b, "import table is damaged");
            continue;
        }
        if (binary_add_import(b, NULL, text, 0) != 0)
        {
            return;
        }
    }
}

int elf_parse(Binary *b, const unsigned char *data, uint64_t size)
{
    Reader r = {.data = data, .size = size};

    unsigned class = reader_u8(&r, 4);
    unsigned encoding = reader_u8(&r, 5);
    if (r.failed || (class != ELF_CLASS_32 && class != ELF_CLASS_64) ||
        (encoding != ELF_DATA_LITTLE && encoding != ELF_DATA_BIG))
    {
        b->fatal = "invalid ELF header";
        return -1;
    }

    int is_64 = class == ELF_CLASS_64;
    r.big_endian = encoding == ELF_DATA_BIG;

    unsigned type = reader_u16(&r, 16);
    unsigned machine = reader_u16(&r, 18);
    b->entry = read_word(&r, 24, is_64);
    uint64_t table = read_word(&r, is_64 ? 40 : 32, is_64);
    unsigned entry_size = reader_u16(&r, is_64 ? 58 : 46);
    unsigned count = reader_u16(&r, is_64 ? 60 : 48);
    unsigned names_index = reader_u16(&r, is_64 ? 62 : 50);
    if (r.failed)
    {
        b->fatal = "truncated ELF header";
        return -1;
    }

    snprintf(b->format, sizeof(b->format), "ELF%d, %s, %s, %s-endian", is_64 ? 64 : 32,
             machine_name(machine), type_name(type), r.big_endian ? "big" : "little");

    // Stripping the section table is legal, since the loader does not need it
    if (table == 0 || count == 0 || table >= size || entry_size < (is_64 ? 64u : 40u))
    {
        binary_warn(b, "no usable section table (stripped or damaged)");
        return 0;
    }

    SectionHeader names = {0};
    if (names_index < count)
    {
        names = read_section_header(&r, table + (uint64_t) names_index * entry_size, is_64);
    }
    if (r.failed)
    {
        r.failed = 0;
        binary_warn(b, "section names are damaged");
    }

    int found_symbols = 0;
    SectionHeader symbols = {0};

    for (unsigned i = 0; i < count; i++)
    {
        SectionHeader h = read_section_header(&r, table + (uint64_t) i * entry_size, is_64);
        if (r.failed)
        {
            r.failed = 0;
            binary_warn(b, "section table is truncated");
            break;
        }
        if (h.type == SECTION_NULL)
        {
            continue;
        }

        const char *name = h.name < names.size ? reader_string(&r, names.offset + h.name) : NULL;
        if (name == NULL)
        {
            r.failed = 0;
            name = "(unknown)";
        }

        Section *section = binary_add_section(b, name, SECTION_NAME_SIZE - 1);
        if (section == NULL)
        {
            break;
        }
        section->offset = h.offset;
        section->size = h.type == SECTION_NOBITS ? 0 : h.size;
        section->vaddr = h.addr;
        section->vsize = h.size;
        section->readable = (h.flags & FLAG_ALLOC) != 0;
        section->writable = (h.flags & FLAG_WRITE) != 0;
        section->executable = (h.flags & FLAG_EXEC) != 0;

        if (h.type == SECTION_DYNSYM && !found_symbols)
        {
            found_symbols = 1;
            symbols = h;
        }
    }

    if (found_symbols)
    {
        SectionHeader strings = {0};
        if (symbols.link < count)
        {
            strings = read_section_header(&r, table + (uint64_t) symbols.link * entry_size, is_64);
        }
        if (r.failed || symbols.link >= count)
        {
            r.failed = 0;
            binary_warn(b, "import table is damaged");
            return 0;
        }
        read_imports(b, &r, symbols, strings, is_64);
    }
    return 0;
}
