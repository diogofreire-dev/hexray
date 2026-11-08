// What the ELF and PE parsers have in common: a safe way of reading an untrusted file,
// and one description of an executable that does not depend on its format.

#ifndef HEXRAY_BINARY_H
#define HEXRAY_BINARY_H

#include <stddef.h>
#include <stdint.h>

// Limits on what a file can make us do. A real program stays far below all of them;
// a malicious file could otherwise claim millions of entries to exhaust the machine.
#define MAX_SECTIONS 256
#define MAX_IMPORTS 20000
#define MAX_WARNINGS 8
#define SECTION_NAME_SIZE 33    // 32 characters and the final '\0'

// ---- Reading the file safely -----------------------------------------------------
//
// Every offset and size in an executable is written by whoever made the file, so none
// of them can be trusted. A parser that does `data + offset` directly lets the file
// read any memory it likes, which is how real parsers get exploited. Here all access
// goes through these functions, which check the bounds first.
//
// A failed read returns 0 and sets `failed`, which stays set. That means a parser can
// do several reads in a row and check for failure once, after all of them.

typedef struct
{
    const unsigned char *data;
    uint64_t size;
    int big_endian;
    int failed;
} Reader;

unsigned reader_u8(Reader *r, uint64_t offset);
unsigned reader_u16(Reader *r, uint64_t offset);
uint32_t reader_u32(Reader *r, uint64_t offset);
uint64_t reader_u64(Reader *r, uint64_t offset);

// Returns a pointer to `length` bytes inside the file, or NULL if they do not all exist
const unsigned char *reader_bytes(Reader *r, uint64_t offset, uint64_t length);

// Returns the text at `offset` only if its final '\0' is inside the file, or NULL.
// The pointer stays inside the file's data, so nothing needs to be copied or freed.
const char *reader_string(Reader *r, uint64_t offset);

// ---- The description of an executable --------------------------------------------

typedef struct
{
    char name[SECTION_NAME_SIZE];
    uint64_t offset;      // where it starts in the file
    uint64_t size;        // how many bytes it takes in the file
    uint64_t vaddr;       // where it goes in memory
    uint64_t vsize;       // how much memory it takes
    int readable;
    int writable;
    int executable;
} Section;

typedef struct
{
    const char *library;  // NULL if the format does not say (ELF)
    const char *name;     // NULL if imported by number
    unsigned ordinal;
} Import;

typedef struct
{
    char format[96];
    uint64_t entry;
    Section sections[MAX_SECTIONS];
    size_t section_count;
    Import *imports;
    size_t import_count;
    size_t import_capacity;
    const char *warnings[MAX_WARNINGS];
    size_t warning_count;
    const char *fatal;    // why parsing could not even start
} Binary;

// Returns the next free section with `name` filled in, or NULL if the list is full.
// `name` may have no final '\0', so at most `max_length` bytes of it are read.
Section *binary_add_section(Binary *b, const char *name, size_t max_length);

// Returns 0 on success, -1 if the list is full (a warning is recorded)
int binary_add_import(Binary *b, const char *library, const char *name, unsigned ordinal);

// Records a problem with the file, once. `text` must be a string literal.
void binary_warn(Binary *b, const char *text);

void binary_free(Binary *b);

// Each parser fills `b`. A damaged file still gives whatever could be read, plus
// warnings, because a broken header is itself useful to an analyst. They return -1,
// with b->fatal set, only when nothing at all could be read.
int elf_parse(Binary *b, const unsigned char *data, uint64_t size);
int pe_parse(Binary *b, const unsigned char *data, uint64_t size);

#endif
