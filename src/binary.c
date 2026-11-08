#include "binary.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

// Longest name we accept. C++ symbol names can be very long, but not this long.
#define MAX_STRING_LENGTH 4096

// Written as `size - offset < length` and not `offset + length > size` on purpose:
// a huge offset could make that sum overflow, wrap around and pass the check.
static int reader_has(Reader *r, uint64_t offset, uint64_t length)
{
    if (r->failed || offset > r->size || r->size - offset < length)
    {
        r->failed = 1;
        return 0;
    }
    return 1;
}

unsigned reader_u8(Reader *r, uint64_t offset)
{
    return reader_has(r, offset, 1) ? r->data[offset] : 0;
}

unsigned reader_u16(Reader *r, uint64_t offset)
{
    if (!reader_has(r, offset, 2))
    {
        return 0;
    }
    const unsigned char *p = r->data + offset;
    return r->big_endian ? (unsigned) p[0] << 8 | p[1] : (unsigned) p[1] << 8 | p[0];
}

uint32_t reader_u32(Reader *r, uint64_t offset)
{
    if (!reader_has(r, offset, 4))
    {
        return 0;
    }
    const unsigned char *p = r->data + offset;
    if (r->big_endian)
    {
        return (uint32_t) p[0] << 24 | (uint32_t) p[1] << 16 | (uint32_t) p[2] << 8 | p[3];
    }
    return (uint32_t) p[3] << 24 | (uint32_t) p[2] << 16 | (uint32_t) p[1] << 8 | p[0];
}

uint64_t reader_u64(Reader *r, uint64_t offset)
{
    if (!reader_has(r, offset, 8))
    {
        return 0;
    }
    uint64_t first = reader_u32(r, offset);
    uint64_t second = reader_u32(r, offset + 4);
    return r->big_endian ? first << 32 | second : second << 32 | first;
}

const unsigned char *reader_bytes(Reader *r, uint64_t offset, uint64_t length)
{
    return reader_has(r, offset, length) ? r->data + offset : NULL;
}

const char *reader_string(Reader *r, uint64_t offset)
{
    if (!reader_has(r, offset, 1))
    {
        return NULL;
    }

    uint64_t available = r->size - offset;
    size_t limit = available < MAX_STRING_LENGTH ? (size_t) available : MAX_STRING_LENGTH;

    // Without this check, printing a name at the very end of the file with no '\0'
    // would keep reading whatever comes after it in memory
    if (memchr(r->data + offset, '\0', limit) == NULL)
    {
        r->failed = 1;
        return NULL;
    }
    return (const char *) (r->data + offset);
}

Section *binary_add_section(Binary *b, const char *name, size_t max_length)
{
    if (b->section_count == MAX_SECTIONS)
    {
        binary_warn(b, "too many sections: only the first ones are shown");
        return NULL;
    }

    Section *section = &b->sections[b->section_count++];
    size_t i = 0;
    for (; i < max_length && i < SECTION_NAME_SIZE - 1 && name[i] != '\0'; i++)
    {
        // The name comes from the file, so control characters must not reach the terminal
        section->name[i] = iscntrl((unsigned char) name[i]) ? '?' : name[i];
    }
    section->name[i] = '\0';
    return section;
}

int binary_add_import(Binary *b, const char *library, const char *name, unsigned ordinal)
{
    if (b->import_count == MAX_IMPORTS)
    {
        binary_warn(b, "too many imports: the list is incomplete");
        return -1;
    }

    if (b->import_count == b->import_capacity)
    {
        size_t capacity = b->import_capacity == 0 ? 64 : b->import_capacity * 2;
        Import *grown = realloc(b->imports, capacity * sizeof(Import));
        if (grown == NULL)
        {
            binary_warn(b, "out of memory: the list of imports is incomplete");
            return -1;
        }
        b->imports = grown;
        b->import_capacity = capacity;
    }

    b->imports[b->import_count++] = (Import) {library, name, ordinal};
    return 0;
}

void binary_warn(Binary *b, const char *text)
{
    for (size_t i = 0; i < b->warning_count; i++)
    {
        if (strcmp(b->warnings[i], text) == 0)
        {
            return;
        }
    }
    if (b->warning_count < MAX_WARNINGS)
    {
        b->warnings[b->warning_count++] = text;
    }
}

void binary_free(Binary *b)
{
    free(b->imports);
    b->imports = NULL;
}
