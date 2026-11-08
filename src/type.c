// hexray type: identifies files by their magic bytes.
//
// Usage: hexray type [FILE...]
//   Without FILE, reads standard input (there is no extension to check then).
//
// Most formats start with a fixed signature, and the operating system does not care
// what a file is called. That gap is what attackers use: `invoice.pdf` can really be
// a Windows program. So each file gets a type from its content, and a MISMATCH mark
// when its extension claims a different format.

// getopt and strcasecmp are POSIX, not standard C (see the same line in dump.c)
#define _POSIX_C_SOURCE 200809L

#include "type.h"
#include "util.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#define COMMAND_NAME "hexray type"
#define MAX_MAGIC 8
#define MAX_EXTENSIONS 12
#define PE_HEADER_POINTER 0x3c

typedef struct
{
    const char *name;
    unsigned char magic[MAX_MAGIC];
    size_t magic_length;    // 0 = this format has no signature (plain text)
    // Optional second check, for formats that share a signature. NULL = none needed.
    int (*confirm)(const unsigned char *header, size_t length);
    int is_executable;      // a native program, which is what packers are used on
    // Unused slots are NULL: in an initialiser, whatever is left out becomes zero
    const char *extensions[MAX_EXTENSIONS];
} FileType;

// Reads 4 bytes as a big-endian number (most significant byte first). The cast matters:
// a byte is promoted to a signed int, and shifting a value into its sign bit is
// undefined behaviour, so we make it unsigned before shifting.
static uint32_t read_be32(const unsigned char *bytes)
{
    return (uint32_t) bytes[0] << 24 | (uint32_t) bytes[1] << 16 |
           (uint32_t) bytes[2] << 8 | (uint32_t) bytes[3];
}

// Universal binaries and Java classes both start with ca fe ba be. The next 4 bytes
// settle it: a universal binary stores how many architectures it holds (a small
// number), a Java class stores its version, and the first Java version was 45.
#define FIRST_JAVA_VERSION 45

static int is_universal_binary(const unsigned char *header, size_t length)
{
    return length >= 8 && read_be32(header + 4) < FIRST_JAVA_VERSION;
}

static int is_java_class(const unsigned char *header, size_t length)
{
    return length >= 8 && read_be32(header + 4) >= FIRST_JAVA_VERSION;
}

// "MZ" is only two bytes and plenty of files start with them by chance. A real Windows
// program stores, at offset 0x3c, where its PE header is, and that header starts with
// "PE\0\0". (Little-endian, so the first byte of the field is the least significant.)
static int is_pe(const unsigned char *header, size_t length)
{
    if (length < PE_HEADER_POINTER + 4)
    {
        return 0;
    }

    const unsigned char *field = header + PE_HEADER_POINTER;
    uint32_t pe_header = (uint32_t) field[3] << 24 | (uint32_t) field[2] << 16 |
                         (uint32_t) field[1] << 8 | field[0];

    return pe_header <= length - 4 && memcmp(header + pe_header, "PE\0\0", 4) == 0;
}

static const FileType types[] = {
    {"Windows executable (PE)", {0x4d, 0x5a}, 2, is_pe, 1,
     {"exe", "dll", "sys", "scr", "ocx", "cpl", "com", "efi"}},
    {"MZ file without a PE header (old DOS program?)", {0x4d, 0x5a}, 2, NULL, 1,
     {"exe", "dll", "sys", "scr", "ocx", "cpl", "com", "efi"}},
    {"Linux executable (ELF)", {0x7f, 0x45, 0x4c, 0x46}, 4, NULL, 1,
     {"so", "o", "elf"}},
    {"macOS executable (Mach-O 64-bit)", {0xcf, 0xfa, 0xed, 0xfe}, 4, NULL, 1,
     {"dylib", "so", "o", "bundle"}},
    {"macOS universal binary", {0xca, 0xfe, 0xba, 0xbe}, 4, is_universal_binary, 1,
     {"dylib", "so", "o", "bundle"}},
    {"Java class file", {0xca, 0xfe, 0xba, 0xbe}, 4, is_java_class, 0,
     {"class"}},
    {"ZIP archive", {0x50, 0x4b, 0x03, 0x04}, 4, NULL, 0,
     {"zip", "docx", "docm", "xlsx", "xlsm", "pptx", "jar", "apk", "odt", "ods", "odp"}},
    {"Old Office document (OLE2)", {0xd0, 0xcf, 0x11, 0xe0}, 4, NULL, 0,
     {"doc", "xls", "ppt", "msi", "msg"}},
    {"PDF document", {0x25, 0x50, 0x44, 0x46}, 4, NULL, 0,
     {"pdf"}},
    {"PNG image", {0x89, 0x50, 0x4e, 0x47}, 4, NULL, 0,
     {"png"}},
    {"JPEG image", {0xff, 0xd8, 0xff}, 3, NULL, 0,
     {"jpg", "jpeg"}},
    // Text has no signature, so it can never be detected. It is here so that an
    // executable called notes.txt is still caught by the extension check.
    {"Text file", {0}, 0, NULL, 0,
     {"txt", "csv", "log", "md"}},
};

static const size_t type_count = sizeof(types) / sizeof(types[0]);

// Returns the matching type, or NULL if no signature matches
static const FileType *identify(const unsigned char *header, size_t length)
{
    for (size_t i = 0; i < type_count; i++)
    {
        const FileType *type = &types[i];
        if (type->magic_length == 0 || length < type->magic_length)
        {
            continue;
        }
        if (memcmp(header, type->magic, type->magic_length) != 0)
        {
            continue;
        }
        if (type->confirm == NULL || type->confirm(header, length))
        {
            return type;
        }
    }
    return NULL;
}

const char *type_identify(const unsigned char *header, size_t length, int *is_executable)
{
    const FileType *type = identify(header, length);
    *is_executable = type != NULL && type->is_executable;
    return type != NULL ? type->name : NULL;
}

// Returns what follows the last dot of the file name, or NULL if there is none.
// Only the name counts (a dot in a folder name is not an extension), and a name
// that starts with a dot, like .bashrc, is a hidden file with no extension.
static const char *find_extension(const char *path)
{
    const char *slash = strrchr(path, '/');
    const char *name = slash != NULL ? slash + 1 : path;
    const char *dot = strrchr(name, '.');

    if (dot == NULL || dot == name || dot[1] == '\0')
    {
        return NULL;
    }
    return dot + 1;
}

static int has_extension(const FileType *type, const char *extension)
{
    for (size_t i = 0; i < MAX_EXTENSIONS && type->extensions[i] != NULL; i++)
    {
        // strcasecmp ignores case, so INVOICE.PDF counts as .pdf
        if (strcasecmp(type->extensions[i], extension) == 0)
        {
            return 1;
        }
    }
    return 0;
}

// Returns the type the extension wrongly claims to be, or NULL if there is no mismatch.
// An extension we know nothing about (.bak, .6 in libc.so.6) proves nothing, so it is
// never flagged. `detected` is NULL when the content matched no signature.
static const FileType *find_mismatch(const FileType *detected, const char *extension)
{
    if (extension == NULL || (detected != NULL && has_extension(detected, extension)))
    {
        return NULL;
    }

    for (size_t i = 0; i < type_count; i++)
    {
        // Unknown content in a .txt is normal: text has no signature to find
        if (has_extension(&types[i], extension) && (detected != NULL || types[i].magic_length > 0))
        {
            return &types[i];
        }
    }
    return NULL;
}

// Prints the verdict for one input. `path` is NULL for stdin, which has no extension.
// Returns 0 on success, -1 on a read error.
static int report(FILE *in, const char *label, const char *path)
{
    unsigned char header[TYPE_HEADER_SIZE];
    size_t length = fread(header, 1, sizeof(header), in);
    if (ferror(in))
    {
        print_file_error(COMMAND_NAME, label, errno);
        return -1;
    }

    print_untrusted(stdout, label);
    if (length == 0)
    {
        printf(": empty file\n");   // no bytes means nothing to compare the extension with
        return 0;
    }

    const FileType *detected = identify(header, length);
    printf(": %s", detected != NULL ? detected->name : "Unknown (no known signature)");

    const char *extension = path != NULL ? find_extension(path) : NULL;
    const FileType *claimed = find_mismatch(detected, extension);
    if (claimed != NULL)
    {
        printf("  [MISMATCH: .");
        print_untrusted(stdout, extension);
        printf(" is the extension of: %s]", claimed->name);
    }
    printf("\n");
    return 0;
}

int cmd_type(int argc, char *argv[])
{
    // No options exist yet. Calling getopt anyway rejects a mistyped -x and handles
    // `--`, which lets us analyse a file whose name starts with a dash.
    if (getopt(argc, argv, "") != -1)
    {
        fprintf(stderr, "Usage: " COMMAND_NAME " [FILE...]\n");
        return 1;
    }

    if (optind == argc)
    {
        return report(stdin, "(stdin)", NULL) == 0 ? 0 : 1;
    }

    // One unreadable file must not stop the triage of the others
    int status = 0;
    for (int i = optind; i < argc; i++)
    {
        FILE *in = fopen(argv[i], "rb");   // read only: samples are never executed
        if (in == NULL)
        {
            print_file_error(COMMAND_NAME, argv[i], errno);
            status = 1;
            continue;
        }
        if (report(in, argv[i], argv[i]) != 0)
        {
            status = 1;
        }
        fclose(in);
    }
    return status;
}
