// Reads the headers of a PE file, the executable format of Windows.
//
// The layout: an old DOS header ("MZ") whose field at 0x3c says where the real PE header
// is. After it come the COFF header, the "optional" header (not optional at all) and
// the section table. The optional header points to the import table, an array with
// one entry per DLL, and each of those leads to the list of functions wanted from it.
//
// Pointers inside the import table are RVAs: addresses relative to where the program
// will be loaded in memory. The file is not laid out like memory, so each RVA must be
// translated into a file offset with the help of the section table.

#include "binary.h"

#include <stdio.h>

enum
{
    PE_HEADER_POINTER = 0x3c,
    PE32_MAGIC = 0x10b,
    PE32_PLUS_MAGIC = 0x20b,
    SECTION_HEADER_SIZE = 40,
    IMPORT_DESCRIPTOR_SIZE = 20,
    IMPORT_DIRECTORY_INDEX = 1,
    MAX_DESCRIPTORS = 4096,
    MAX_THUNKS = 65536,
};

#define SECTION_EXECUTE 0x20000000u
#define SECTION_READ    0x40000000u
#define SECTION_WRITE   0x80000000u

static const char *machine_name(unsigned machine)
{
    switch (machine)
    {
        case 0x14c:   return "x86";
        case 0x1c0:   return "ARM";
        case 0x8664:  return "x86-64";
        case 0xaa64:  return "ARM64";
        default:      return "unknown machine";
    }
}

// Finds which section holds an RVA and works out the file offset. Returns 0 on
// success, -1 if no section has it in the file.
static int rva_to_offset(const Binary *b, uint64_t rva, uint64_t *offset)
{
    for (size_t i = 0; i < b->section_count; i++)
    {
        const Section *section = &b->sections[i];
        uint64_t span = section->vsize > section->size ? section->vsize : section->size;

        if (rva >= section->vaddr && rva - section->vaddr < span)
        {
            uint64_t delta = rva - section->vaddr;
            if (delta >= section->size)
            {
                return -1;   // inside the section in memory, but not stored in the file
            }
            *offset = section->offset + delta;
            return 0;
        }
    }
    return -1;
}

static void read_sections(Binary *b, Reader *r, uint64_t table, unsigned count)
{
    for (unsigned i = 0; i < count; i++)
    {
        uint64_t at = table + (uint64_t) i * SECTION_HEADER_SIZE;
        const unsigned char *name = reader_bytes(r, at, 8);   // 8 bytes, '\0' is optional
        uint32_t vsize = reader_u32(r, at + 8);
        uint32_t vaddr = reader_u32(r, at + 12);
        uint32_t raw_size = reader_u32(r, at + 16);
        uint32_t raw_offset = reader_u32(r, at + 20);
        uint32_t flags = reader_u32(r, at + 36);

        if (r->failed)
        {
            r->failed = 0;
            binary_warn(b, "section table is truncated");
            return;
        }

        Section *section = binary_add_section(b, (const char *) name, 8);
        if (section == NULL)
        {
            return;
        }
        section->offset = raw_offset;
        section->size = raw_size;
        section->vaddr = vaddr;
        section->vsize = vsize;
        section->readable = (flags & SECTION_READ) != 0;
        section->writable = (flags & SECTION_WRITE) != 0;
        section->executable = (flags & SECTION_EXECUTE) != 0;
    }
}

// Reads the list of functions wanted from one DLL. Returns -1 when no more can be stored.
static int read_thunks(Binary *b, Reader *r, const char *library, uint64_t thunks, int is_plus)
{
    uint64_t entry_size = is_plus ? 8 : 4;
    uint64_t by_ordinal = is_plus ? (uint64_t) 1 << 63 : (uint64_t) 1 << 31;

    for (uint64_t i = 0; i < MAX_THUNKS; i++)
    {
        uint64_t at;
        if (rva_to_offset(b, thunks + i * entry_size, &at) != 0)
        {
            binary_warn(b, "import table is damaged");
            return 0;
        }

        uint64_t entry = is_plus ? reader_u64(r, at) : reader_u32(r, at);
        if (r->failed)
        {
            r->failed = 0;
            binary_warn(b, "import table is damaged");
            return 0;
        }
        if (entry == 0)
        {
            return 0;   // the list ends with a zero
        }

        if (entry & by_ordinal)
        {
            if (binary_add_import(b, library, NULL, (unsigned) (entry & 0xffff)) != 0)
            {
                return -1;
            }
            continue;
        }

        // The entry points to a 2-byte hint followed by the function's name
        uint64_t hint;
        const char *name = NULL;
        if (rva_to_offset(b, entry & 0x7fffffff, &hint) == 0)
        {
            name = reader_string(r, hint + 2);
        }
        if (name == NULL)
        {
            r->failed = 0;
            binary_warn(b, "import table is damaged");
            return 0;
        }
        if (binary_add_import(b, library, name, 0) != 0)
        {
            return -1;
        }
    }

    binary_warn(b, "import table is damaged");
    return 0;
}

static void read_imports(Binary *b, Reader *r, uint64_t directory, int is_plus)
{
    for (uint64_t i = 0; i < MAX_DESCRIPTORS; i++)
    {
        uint64_t at;
        if (rva_to_offset(b, directory + i * IMPORT_DESCRIPTOR_SIZE, &at) != 0)
        {
            binary_warn(b, "import table is damaged");
            return;
        }

        // Two lists of functions exist: the original one, which some linkers leave
        // empty, and the one the loader overwrites with addresses when it runs.
        uint32_t original_thunks = reader_u32(r, at);
        uint32_t library_name = reader_u32(r, at + 12);
        uint32_t first_thunks = reader_u32(r, at + 16);
        if (r->failed)
        {
            r->failed = 0;
            binary_warn(b, "import table is damaged");
            return;
        }
        if (original_thunks == 0 && library_name == 0 && first_thunks == 0)
        {
            return;   // an entry of all zeros ends the array
        }

        uint64_t name_offset;
        const char *library = NULL;
        if (rva_to_offset(b, library_name, &name_offset) == 0)
        {
            library = reader_string(r, name_offset);
        }
        if (library == NULL)
        {
            r->failed = 0;
            binary_warn(b, "import table is damaged");
            library = "(unknown)";
        }

        uint32_t thunks = original_thunks != 0 ? original_thunks : first_thunks;
        if (read_thunks(b, r, library, thunks, is_plus) != 0)
        {
            return;
        }
    }
    binary_warn(b, "import table is damaged");
}

int pe_parse(Binary *b, const unsigned char *data, uint64_t size)
{
    Reader r = {.data = data, .size = size};

    uint64_t pe_header = reader_u32(&r, PE_HEADER_POINTER);
    const unsigned char *signature = reader_bytes(&r, pe_header, 4);
    if (r.failed || signature[0] != 'P' || signature[1] != 'E' ||
        signature[2] != 0 || signature[3] != 0)
    {
        b->fatal = "starts with MZ but has no valid PE header";
        return -1;
    }

    uint64_t coff = pe_header + 4;
    unsigned machine = reader_u16(&r, coff);
    unsigned section_count = reader_u16(&r, coff + 2);
    unsigned optional_size = reader_u16(&r, coff + 16);
    uint64_t optional = coff + 20;
    unsigned magic = reader_u16(&r, optional);
    uint32_t entry = reader_u32(&r, optional + 16);

    if (r.failed || (magic != PE32_MAGIC && magic != PE32_PLUS_MAGIC))
    {
        b->fatal = "truncated or invalid PE header";
        return -1;
    }

    int is_plus = magic == PE32_PLUS_MAGIC;
    b->entry = entry;
    snprintf(b->format, sizeof(b->format), "%s, %s", is_plus ? "PE32+" : "PE32", machine_name(machine));

    read_sections(b, &r, optional + optional_size, section_count);

    // The optional header ends with a table of directories, and imports are one of them
    uint32_t directory_count = reader_u32(&r, optional + (is_plus ? 108 : 92));
    uint64_t directories = optional + (is_plus ? 112 : 96);
    uint32_t import_rva = reader_u32(&r, directories + IMPORT_DIRECTORY_INDEX * 8);
    if (r.failed)
    {
        r.failed = 0;
        binary_warn(b, "optional header is truncated");
        return 0;
    }

    if (directory_count > IMPORT_DIRECTORY_INDEX && import_rva != 0)
    {
        read_imports(b, &r, import_rva, is_plus);
    }
    return 0;
}
