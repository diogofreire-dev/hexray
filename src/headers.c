// hexray headers: lists the sections and imported functions of ELF and PE files.
//
// Usage: hexray headers [-f] [FILE]
//   -f    show only the flagged imports
//   FILE  file to read; without it, read standard input
//
// Imports say what a program asks the operating system to do, without having to run it.
// A section that is both writable and executable, or that looks like pure noise, is a
// common sign of code that unpacks or modifies itself.

// getopt is POSIX, not standard C (see the same line in dump.c)
#define _POSIX_C_SOURCE 200809L

#include "headers.h"
#include "binary.h"
#include "entropy.h"
#include "type.h"
#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define COMMAND_NAME "hexray headers"

// A file can declare many sections covering all of its bytes, to make us measure the
// same data thousands of times. This caps the work at a few passes over the file.
#define ENTROPY_PASSES 4

typedef struct
{
    int flagged_only;   // -f
    const char *path;   // NULL = standard input
} Options;

typedef struct
{
    const char *name;
    const char *flag;
} ImportRule;

static const ImportRule import_rules[] = {
    {"VirtualAllocEx", "INJECTION"},          // memory in another process
    {"WriteProcessMemory", "INJECTION"},      // writing code into it
    {"CreateRemoteThread", "INJECTION"},      // and running it
    {"NtCreateThreadEx", "INJECTION"},
    {"QueueUserAPC", "INJECTION"},
    {"SetThreadContext", "INJECTION"},
    {"memfd_create", "INJECTION"},            // Linux: a program that exists only in memory
    {"IsDebuggerPresent", "ANTI-ANALYSIS"},
    {"CheckRemoteDebuggerPresent", "ANTI-ANALYSIS"},
    {"ptrace", "ANTI-ANALYSIS"},              // Linux: often used to detect a debugger
    {"URLDownloadToFile", "DOWNLOAD"},
    {"InternetOpenUrl", "DOWNLOAD"},
    {"WinExec", "EXECUTION"},
    {"ShellExecute", "EXECUTION"},
    {"execve", "EXECUTION"},
    {"SetWindowsHookEx", "KEYLOGGING"},
    {"GetAsyncKeyState", "KEYLOGGING"},
    {"RegSetValueEx", "PERSISTENCE"},
};

static const size_t import_rule_count = sizeof(import_rules) / sizeof(import_rules[0]);

// Windows functions taking text come in two versions: MessageBoxA and MessageBoxW
static int import_name_matches(const char *name, const char *rule)
{
    size_t length = strlen(rule);
    if (strncmp(name, rule, length) != 0)
    {
        return 0;
    }
    char next = name[length];
    return next == '\0' || ((next == 'A' || next == 'W') && name[length + 1] == '\0');
}

static const char *flag_for_import(const char *name)
{
    for (size_t i = 0; name != NULL && i < import_rule_count; i++)
    {
        if (import_name_matches(name, import_rules[i].name))
        {
            return import_rules[i].flag;
        }
    }
    return NULL;
}

static int has_import(const Binary *b, const char *wanted)
{
    for (size_t i = 0; i < b->import_count; i++)
    {
        if (b->imports[i].name != NULL && import_name_matches(b->imports[i].name, wanted))
        {
            return 1;
        }
    }
    return 0;
}

static void print_sections(Binary *b, const unsigned char *data, uint64_t size)
{
    if (b->section_count == 0)
    {
        printf("Sections: none\n");
        return;
    }

    uint64_t budget = size * ENTROPY_PASSES;

    printf("%-16s  %-8s  %-8s  %-7s  %s\n", "Name", "Offset", "Size", "Entropy", "Perms");
    for (size_t i = 0; i < b->section_count; i++)
    {
        const Section *s = &b->sections[i];
        int in_file = s->offset <= size && s->size <= size - s->offset;
        char entropy_text[16] = "-";
        int high = 0;

        if (!in_file)
        {
            binary_warn(b, "a section points outside the file");
        }
        else if (s->size > budget)
        {
            binary_warn(b, "sections overlap too much: some entropy values are missing");
        }
        else if (s->size > 0)
        {
            budget -= s->size;
            double entropy = entropy_of_bytes(data + s->offset, (size_t) s->size);
            high = entropy > HIGH_ENTROPY;
            snprintf(entropy_text, sizeof(entropy_text), "%4.2f", entropy);
        }

        printf("%-16s  %08llx  %08llx  %-7s  %c%c%c%s\n", s->name,
               (unsigned long long) s->offset, (unsigned long long) s->size, entropy_text,
               s->readable ? 'r' : '-', s->writable ? 'w' : '-', s->executable ? 'x' : '-',
               high ? "  HIGH" : "");
    }
}

static void print_imports(const Binary *b, const Options *opts)
{
    printf("Imports:  %zu\n", b->import_count);

    for (size_t i = 0; i < b->import_count; i++)
    {
        const Import *import = &b->imports[i];
        const char *flag = flag_for_import(import->name);

        if (opts->flagged_only && flag == NULL)
        {
            continue;
        }

        printf("  ");
        if (import->library != NULL)
        {
            print_untrusted(stdout, import->library);
            printf("!");
        }
        if (import->name != NULL)
        {
            print_untrusted(stdout, import->name);
        }
        else
        {
            printf("#%u", import->ordinal);
        }
        if (flag != NULL)
        {
            printf("  [%s]", flag);
        }
        printf("\n");
    }
}

// What stands out once everything has been read
static void print_warnings(const Binary *b)
{
    for (size_t i = 0; i < b->section_count; i++)
    {
        if (b->sections[i].writable && b->sections[i].executable)
        {
            // Names were cleaned of control characters when they were stored
            printf("Warning:  section %s is both writable and executable\n", b->sections[i].name);
        }
    }

    if ((has_import(b, "VirtualAlloc") || has_import(b, "VirtualAllocEx")) &&
        has_import(b, "WriteProcessMemory") && has_import(b, "CreateRemoteThread"))
    {
        printf("Warning:  imports match the classic code injection pattern\n");
    }

    for (size_t i = 0; i < b->warning_count; i++)
    {
        printf("Warning:  %s\n", b->warnings[i]);
    }
}

// Returns 0 on success, -1 on an error (already reported)
static int analyse(FILE *in, const char *label, const Options *opts)
{
    // The whole input, because headers point all over the file and stdin cannot jump around
    unsigned char *data;
    size_t size;
    if (read_all(in, COMMAND_NAME, label, &data, &size) != 0)
    {
        return -1;
    }

    // `static` keeps this large struct out of the stack. It is zeroed before each use.
    static Binary binary;
    memset(&binary, 0, sizeof(binary));

    int status = -1;
    if (size >= 4 && memcmp(data, "\x7f" "ELF", 4) == 0)
    {
        status = elf_parse(&binary, data, size);
    }
    else if (size >= 2 && memcmp(data, "MZ", 2) == 0)
    {
        status = pe_parse(&binary, data, size);
    }
    else
    {
        binary.fatal = "not an ELF or PE file";
    }

    if (status == 0)
    {
        printf("Format:   %s\n", binary.format);
        printf("Entry:    0x%llx\n\n", (unsigned long long) binary.entry);
        print_sections(&binary, data, size);
        printf("\n");
        print_imports(&binary, opts);
        print_warnings(&binary);
    }
    else
    {
        fprintf(stderr, COMMAND_NAME ": ");
        print_untrusted(stderr, label);
        fprintf(stderr, ": %s\n", binary.fatal);
    }

    binary_free(&binary);   // names in the list point into `data`, so free this first
    free(data);
    return status;
}

// Returns 0 on success, -1 on invalid options
static int parse_options(int argc, char *argv[], Options *opts)
{
    *opts = (Options) {0};

    int opt;
    while ((opt = getopt(argc, argv, "f")) != -1)
    {
        if (opt != 'f')
        {
            return -1;   // getopt already printed what was wrong
        }
        opts->flagged_only = 1;
    }

    if (argc - optind > 1)
    {
        return -1;
    }
    if (argc - optind == 1)
    {
        opts->path = argv[optind];
    }
    return 0;
}

int cmd_headers(int argc, char *argv[])
{
    Options opts;
    if (parse_options(argc, argv, &opts) != 0)
    {
        fprintf(stderr, "Usage: " COMMAND_NAME " [-f] [FILE]\n");
        return 1;
    }

    FILE *in = stdin;
    const char *label = "(stdin)";
    if (opts.path != NULL)
    {
        label = opts.path;
        in = fopen(opts.path, "rb");   // read only: samples are never executed
        if (in == NULL)
        {
            print_file_error(COMMAND_NAME, label, errno);
            return 1;
        }
    }

    int status = analyse(in, label, &opts) == 0 ? 0 : 1;

    if (in != stdin)
    {
        fclose(in);
    }
    return status;
}
