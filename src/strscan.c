// hexray strings: extracts readable text from a file and flags the suspicious parts.
//
// Usage: hexray strings [-f] [-v] [-n MIN] [FILE]
//   -f      show only the flagged strings
//   -v      show long strings in full (by default they are cut for display)
//   -n MIN  shortest string to report, in characters (default 4, smallest 2)
//   FILE    file to read; without it, read standard input
//
// Text inside a program often gives away what it does: where it connects to, what it
// runs, how it survives a reboot. Windows programs usually store text as UTF-16, where
// each character takes two bytes (H.e.l.l.o.), so looking for ASCII alone would miss it.

// getopt and strncasecmp are POSIX, not standard C (see the same line in dump.c)
#define _POSIX_C_SOURCE 200809L

#include "strscan.h"
#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#define COMMAND_NAME "hexray strings"
#define DEFAULT_MIN 4
#define SMALLEST_MIN 2
#define MAX_DISPLAY 200          // characters shown of a long string, unless -v
#define READ_SIZE 65536
#define BASE64_MIN_LENGTH 40
#define MAX_FLAGS 8

typedef struct
{
    unsigned long long min;   // -n
    int flagged_only;         // -f
    int full;                 // -v
    const char *path;         // NULL = standard input
} Options;

// The string being collected. Nothing limits how long a string in a file can be, so
// the text lives on the heap and grows when needed.
typedef struct
{
    const char *encoding;
    char *text;
    size_t length;
    size_t capacity;
    unsigned long long start;   // file offset of the first character
} Run;

typedef struct
{
    Run ascii;
    Run utf16[2];               // one per alignment: even and odd file offsets
    unsigned long long offset;  // file offset of the byte being looked at
    unsigned char previous;     // the byte before it
} Scanner;

// ---- Flagging suspicious strings --------------------------------------------------
// Every string reaching these functions holds only printable ASCII, so the ctype
// calls below cannot receive a negative value.

// A flag is raised when `needle` is found and, if `also` is not NULL, `also` is too.
typedef struct
{
    const char *needle;
    const char *also;
    const char *flag;
} Rule;

static const Rule rules[] = {
    {"http://", NULL, "URL"},                       // download or command-and-control
    {"https://", NULL, "URL"},
    {"ftp://", NULL, "URL"},
    {"cmd.exe", NULL, "SHELL"},                     // running system commands
    {"powershell", NULL, "SHELL"},
    {"/bin/sh", NULL, "SHELL"},
    {"/bin/bash", NULL, "SHELL"},
    {"powershell", " -enc", "ENCODED-COMMAND"},     // a script hidden in Base64
    {"currentversion\\run", NULL, "PERSISTENCE"},   // registry key: run at every logon
    {"currentversion\\\\run", NULL, "PERSISTENCE"}, // the same, as written in .reg files
};

static const size_t rule_count = sizeof(rules) / sizeof(rules[0]);

static int contains_ignore_case(const char *text, const char *needle)
{
    size_t length = strlen(needle);
    for (; *text != '\0'; text++)
    {
        if (strncasecmp(text, needle, length) == 0)
        {
            return 1;
        }
    }
    return 0;
}

// Reads a number from 0 to 255 and moves the cursor past it. The cursor is a pointer
// to a pointer so that this function can change where the caller's pointer points.
static int read_octet(const char **cursor)
{
    const char *p = *cursor;
    int value = 0;
    int digits = 0;

    while (isdigit(*p) && digits < 3)
    {
        value = value * 10 + (*p - '0');
        p++;
        digits++;
    }
    if (digits == 0 || value > 255)
    {
        return 0;
    }
    *cursor = p;
    return 1;
}

static int is_ipv4_at(const char *p)
{
    for (int i = 0; i < 4; i++)
    {
        if (!read_octet(&p))
        {
            return 0;
        }
        if (i < 3 && *p++ != '.')
        {
            return 0;
        }
    }
    // More digits, or a fifth number, means this was something else (1.2.3.4.5).
    // A dot alone is fine: it may be the end of a sentence.
    return !isdigit(*p) && !(*p == '.' && isdigit(p[1]));
}

// The check on the character before filters out version strings such as v1.2.3.4
static int has_ipv4(const char *text)
{
    for (const char *p = text; *p != '\0'; p++)
    {
        int starts_cleanly = p == text || !(isalnum(p[-1]) || p[-1] == '.');
        if (isdigit(*p) && starts_cleanly && is_ipv4_at(p))
        {
            return 1;
        }
    }
    return 0;
}

// Encoded data is a long run of the Base64 alphabet that mixes upper case, lower case
// and digits, and whose length with padding is a multiple of 4. The mix and the length
// are what keep out long file paths and hex hashes, which use the same characters.
// A run right after '_' is skipped too: compiled C++ function names look like
// __ZN5dyld44APIs25NSVersionOfRunTimeLibraryEPKc and would otherwise all match.
static int has_base64_blob(const char *text)
{
    const char *p = text;
    while (*p != '\0')
    {
        int after_underscore = p != text && p[-1] == '_';
        size_t length = 0;
        int upper = 0, lower = 0, digit = 0;

        for (; isalnum(*p) || *p == '+' || *p == '/'; p++)
        {
            upper |= isupper(*p) != 0;
            lower |= islower(*p) != 0;
            digit |= isdigit(*p) != 0;
            length++;
        }

        size_t padding = 0;
        while (*p == '=' && padding < 2)
        {
            padding++;
            p++;
        }

        if (length >= BASE64_MIN_LENGTH && upper && lower && digit &&
            (length + padding) % 4 == 0 && !after_underscore)
        {
            return 1;
        }
        if (*p != '\0' && length == 0 && padding == 0)
        {
            p++;   // a character outside the alphabet: step over it
        }
    }
    return 0;
}

// Adds a flag unless it is already there (cmd.exe and powershell are both SHELL)
static void add_flag(const char *flags[], size_t *count, const char *flag)
{
    for (size_t i = 0; i < *count; i++)
    {
        if (strcmp(flags[i], flag) == 0)
        {
            return;
        }
    }
    if (*count < MAX_FLAGS)
    {
        flags[(*count)++] = flag;
    }
}

// Fills `flags` and returns how many there are
static size_t collect_flags(const char *text, const char *flags[])
{
    size_t count = 0;

    for (size_t i = 0; i < rule_count; i++)
    {
        if (contains_ignore_case(text, rules[i].needle) &&
            (rules[i].also == NULL || contains_ignore_case(text, rules[i].also)))
        {
            add_flag(flags, &count, rules[i].flag);
        }
    }
    if (has_ipv4(text))
    {
        add_flag(flags, &count, "IP");
    }
    if (has_base64_blob(text))
    {
        add_flag(flags, &count, "BASE64");
    }
    return count;
}

// ---- Collecting strings -----------------------------------------------------------

static void print_run(const Run *run, const Options *opts)
{
    const char *flags[MAX_FLAGS];
    size_t flag_count = collect_flags(run->text, flags);   // always on the whole string

    if (opts->flagged_only && flag_count == 0)
    {
        return;
    }

    printf("%08llx  %-6s  ", run->start, run->encoding);
    if (!opts->full && run->length > MAX_DISPLAY)
    {
        // %.*s prints at most that many characters of the string
        printf("%.*s... (%zu characters)", MAX_DISPLAY, run->text, run->length);
    }
    else
    {
        fputs(run->text, stdout);
    }

    for (size_t i = 0; i < flag_count; i++)
    {
        printf("%s%s", i == 0 ? "  [" : ", ", flags[i]);
    }
    printf("%s\n", flag_count > 0 ? "]" : "");
}

// Returns 0 on success, -1 if there is no memory left
static int run_append(Run *run, char c, unsigned long long offset)
{
    if (run->length == 0)
    {
        run->start = offset;
    }

    if (run->length + 1 >= run->capacity)   // + 1 keeps room for the final '\0'
    {
        size_t capacity = run->capacity == 0 ? 256 : run->capacity * 2;
        // The result goes to a new variable: if realloc fails it returns NULL but the
        // old block is still allocated, and overwriting run->text would leak it.
        char *grown = realloc(run->text, capacity);
        if (grown == NULL)
        {
            return -1;
        }
        run->text = grown;
        run->capacity = capacity;
    }

    run->text[run->length++] = c;
    return 0;
}

// The current string has ended: report it if it is long enough, then start again
static void run_finish(Run *run, const Options *opts)
{
    if (run->length >= opts->min)
    {
        run->text[run->length] = '\0';
        print_run(run, opts);
    }
    run->length = 0;
}

static int is_printable(unsigned char byte)
{
    return byte >= 0x20 && byte <= 0x7e;   // written out so the locale cannot change it
}

// Gives one character (or the end of a string) to a run
static int feed(Run *run, int printable, unsigned char byte, unsigned long long offset,
                const Options *opts)
{
    if (printable)
    {
        return run_append(run, (char) byte, offset);
    }
    run_finish(run, opts);
    return 0;
}

// Looks at one byte. Besides being a possible ASCII character, it is the second half
// of a UTF-16 unit that began on the byte before. A string can start on any offset, so
// units are tracked for both alignments: the parity of the unit's first byte picks one.
static int process_byte(Scanner *scanner, unsigned char byte, const Options *opts)
{
    unsigned long long offset = scanner->offset;

    if (feed(&scanner->ascii, is_printable(byte), byte, offset, opts) != 0)
    {
        return -1;
    }

    if (offset > 0)
    {
        // Little-endian: an ASCII character in UTF-16 is that byte followed by 0x00
        unsigned char low = scanner->previous;
        Run *run = &scanner->utf16[(offset - 1) & 1];
        if (feed(run, byte == 0 && is_printable(low), low, offset - 1, opts) != 0)
        {
            return -1;
        }
    }

    scanner->previous = byte;
    scanner->offset++;
    return 0;
}

// Returns 0 on success, -1 on an error (already reported)
static int scan(FILE *in, const char *label, const Options *opts)
{
    Scanner scanner = {
        .ascii = {.encoding = "ascii"},
        .utf16 = {{.encoding = "utf-16"}, {.encoding = "utf-16"}},
    };
    unsigned char buffer[READ_SIZE];
    int status = 0;
    size_t got;

    while (status == 0 && (got = fread(buffer, 1, sizeof(buffer), in)) > 0)
    {
        for (size_t i = 0; i < got && status == 0; i++)
        {
            status = process_byte(&scanner, buffer[i], opts);
        }
    }

    if (status != 0)
    {
        fprintf(stderr, COMMAND_NAME ": out of memory\n");
    }
    else if (ferror(in))
    {
        print_file_error(COMMAND_NAME, label, errno);
        status = -1;
    }
    else
    {
        // The input may end in the middle of a string
        run_finish(&scanner.ascii, opts);
        run_finish(&scanner.utf16[0], opts);
        run_finish(&scanner.utf16[1], opts);
    }

    free(scanner.ascii.text);   // free(NULL) is allowed and does nothing
    free(scanner.utf16[0].text);
    free(scanner.utf16[1].text);
    return status;
}

// Returns 0 on success, -1 on invalid options
static int parse_options(int argc, char *argv[], Options *opts)
{
    *opts = (Options) {.min = DEFAULT_MIN};

    int opt;
    while ((opt = getopt(argc, argv, "fvn:")) != -1)
    {
        switch (opt)
        {
            case 'f':
                opts->flagged_only = 1;
                break;
            case 'v':
                opts->full = 1;
                break;
            case 'n':
                if (parse_size(optarg, 10, &opts->min) != 0 || opts->min < SMALLEST_MIN)
                {
                    fprintf(stderr, "Invalid minimum length: %s\n", optarg);
                    return -1;
                }
                break;
            default:   // getopt already printed what was wrong
                return -1;
        }
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

int cmd_strings(int argc, char *argv[])
{
    Options opts;
    if (parse_options(argc, argv, &opts) != 0)
    {
        fprintf(stderr, "Usage: " COMMAND_NAME " [-f] [-v] [-n MIN] [FILE]\n");
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

    int status = scan(in, label, &opts) == 0 ? 0 : 1;

    if (in != stdin)
    {
        fclose(in);
    }
    return status;
}
