// hexray entropy: measures how random a file's bytes are.
//
// Usage: hexray entropy [-q] [-b SIZE] [FILE]
//   -q       show only the summary, without the graph
//   -b SIZE  size of each block in bytes (decimal, or hex with 0x; default 4096)
//   FILE     file to read; without it, read standard input
//
// Shannon entropy says how many bits of real information each byte carries: 0 when
// every byte is the same, 8 when all 256 values are equally likely. Code and text have
// patterns and land around 4 to 6. Compressed or encrypted data looks like noise and
// lands close to 8. Malware uses that: a packed program hides its real code in an
// encrypted blob and only unpacks it when it runs, so static tools find nothing to read.

// getopt is POSIX, not standard C (see the same line in dump.c)
#define _POSIX_C_SOURCE 200809L

#include "entropy.h"
#include "type.h"
#include "util.h"

#include <errno.h>
#include <math.h>     // log2 lives in a separate library on Linux: see LDLIBS in the Makefile
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define COMMAND_NAME "hexray entropy"
#define BYTE_VALUES 256
#define READ_SIZE 65536
#define DEFAULT_BLOCK_SIZE 4096
// Few bytes cannot fill all 256 values, so a tiny block of pure noise would still score
// low. From 1024 bytes up, random data reliably scores above the threshold below.
#define MIN_BLOCK_SIZE 1024
#define HIGH_ENTROPY 7.2
#define MAX_ENTROPY 8
#define MOSTLY_HIGH_PERCENT 70   // this much of the file must be high to call it packed
#define BAR_WIDTH 32

typedef struct
{
    unsigned long long block_size;   // -b
    int quiet;                       // -q
    const char *path;                // NULL = standard input
} Options;

typedef struct
{
    const char *packer;
    const char *text;
} PackerSignature;

// Text that packers leave behind in the files they produce. None of these repeats its
// first character, and update_packers relies on that.
static const PackerSignature packers[] = {
    {"UPX", "UPX!"},
    {"UPX", "UPX0"},
    {"UPX", "UPX1"},
    {"ASPack", ".aspack"},
    {"MPRESS", "MPRESS1"},
    {"Themida", ".themida"},
    {"VMProtect", ".vmp0"},
};

// A macro and not a const variable: the arrays in Analysis need a compile-time size
#define PACKER_COUNT (sizeof(packers) / sizeof(packers[0]))

typedef struct
{
    unsigned long long total_counts[BYTE_VALUES];   // how often each byte value appeared
    unsigned long long block_counts[BYTE_VALUES];
    unsigned long long total;        // bytes read so far
    unsigned long long block_used;   // bytes in the current block
    unsigned long long high_bytes;   // bytes that were in a high entropy block
    unsigned char header[TYPE_HEADER_SIZE];
    size_t matched[PACKER_COUNT];    // how much of each signature we have just seen
    int found[PACKER_COUNT];
    unsigned long long found_at[PACKER_COUNT];
} Analysis;

// H = -sum(p * log2(p)), over the byte values that appear. p is the fraction of bytes
// with that value. The cast makes this a floating point division: dividing two integers
// would throw away the fraction and give 0 almost every time.
static double shannon_entropy(const unsigned long long counts[], unsigned long long total)
{
    double entropy = 0.0;
    for (int value = 0; value < BYTE_VALUES; value++)
    {
        if (counts[value] > 0)   // log2(0) is -infinity, and these bytes add nothing
        {
            double p = (double) counts[value] / (double) total;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

static void print_bar(double entropy)
{
    int filled = (int) (entropy / MAX_ENTROPY * BAR_WIDTH + 0.5);   // + 0.5 rounds to nearest
    for (int i = 0; i < BAR_WIDTH; i++)
    {
        putchar(i < filled ? '#' : '.');
    }
}

// Closes the current block: measures it, prints its line and starts counting again
static void finish_block(Analysis *a, const Options *opts)
{
    if (a->block_used == 0)
    {
        return;
    }

    double entropy = shannon_entropy(a->block_counts, a->block_used);
    int high = entropy > HIGH_ENTROPY;
    if (high)
    {
        a->high_bytes += a->block_used;
    }

    if (!opts->quiet)
    {
        unsigned long long start = a->total - a->block_used;
        if (start == 0)
        {
            printf("Offset    Entropy  0 to 8\n");
        }
        printf("%08llx  %4.2f     ", start, entropy);
        print_bar(entropy);
        printf("%s\n", high ? "  HIGH" : "");
    }

    memset(a->block_counts, 0, sizeof(a->block_counts));
    a->block_used = 0;
}

// Advances the search for each signature by one byte. Keeping the progress between
// calls means a signature split across two reads is still found. On a mismatch the
// search restarts, and this byte may itself be the first one of a new match (UUPX!).
static void update_packers(Analysis *a, unsigned char byte)
{
    for (size_t i = 0; i < PACKER_COUNT; i++)
    {
        const char *text = packers[i].text;
        if (a->found[i])
        {
            continue;   // only the first occurrence is reported
        }

        if (byte == (unsigned char) text[a->matched[i]])
        {
            a->matched[i]++;
            if (text[a->matched[i]] == '\0')
            {
                a->found[i] = 1;
                a->found_at[i] = a->total - a->matched[i];
            }
        }
        else
        {
            a->matched[i] = byte == (unsigned char) text[0] ? 1 : 0;
        }
    }
}

static void process_byte(Analysis *a, unsigned char byte, const Options *opts)
{
    if (a->total < TYPE_HEADER_SIZE)
    {
        a->header[a->total] = byte;
    }

    a->total_counts[byte]++;
    a->block_counts[byte]++;
    a->total++;
    a->block_used++;
    update_packers(a, byte);

    if (a->block_used == opts->block_size)
    {
        finish_block(a, opts);
    }
}

// The verdict puts together what was measured. High entropy alone proves little:
// a JPEG or a ZIP is compressed by design, so the file type decides what it means.
static const char *verdict(const Analysis *a, int is_executable, const char *type, int has_packer)
{
    int mostly_high = a->high_bytes * 100 >= a->total * MOSTLY_HIGH_PERCENT;

    if (a->total < MIN_BLOCK_SIZE)
    {
        return "Too small to judge";
    }
    if (is_executable && mostly_high)
    {
        return "PACKED? Most of this executable is high entropy";
    }
    if (is_executable && has_packer)
    {
        return "Packer signature found, but the entropy is normal: check it by hand";
    }
    if (mostly_high && type != NULL)
    {
        return "High entropy, which is common in this format";
    }
    if (mostly_high)
    {
        return "ENCRYPTED? High entropy and no known file type (or compressed data)";
    }
    return "No sign of packing or encryption";
}

static void print_summary(const Analysis *a)
{
    int is_executable;
    size_t header_length = a->total < TYPE_HEADER_SIZE ? a->total : TYPE_HEADER_SIZE;
    const char *type = type_identify(a->header, header_length, &is_executable);

    printf("Type:     %s\n", type != NULL ? type : "Unknown (no known signature)");
    printf("Size:     %llu bytes\n", a->total);
    printf("Entropy:  %.2f of %d.00\n", shannon_entropy(a->total_counts, a->total), MAX_ENTROPY);
    printf("High:     %llu%% of the file (blocks above %.2f)\n",
           a->high_bytes * 100 / a->total, HIGH_ENTROPY);

    int has_packer = 0;
    for (size_t i = 0; i < PACKER_COUNT; i++)
    {
        if (a->found[i])
        {
            printf("Packer:   %s (\"%s\" at offset 0x%llx)\n",
                   packers[i].packer, packers[i].text, a->found_at[i]);
            has_packer = 1;
        }
    }
    if (!has_packer)
    {
        printf("Packer:   no known signature\n");
    }

    printf("Verdict:  %s\n", verdict(a, is_executable, type, has_packer));
}

// Returns 0 on success, -1 on a read error (already reported)
static int analyse(FILE *in, const char *label, const Options *opts)
{
    Analysis a = {0};
    unsigned char buffer[READ_SIZE];
    size_t got;

    while ((got = fread(buffer, 1, sizeof(buffer), in)) > 0)
    {
        for (size_t i = 0; i < got; i++)
        {
            process_byte(&a, buffer[i], opts);
        }
    }

    if (ferror(in))
    {
        print_file_error(COMMAND_NAME, label, errno);
        return -1;
    }

    if (a.total == 0)
    {
        printf("Empty input: nothing to measure\n");   // and no division by zero
        return 0;
    }

    finish_block(&a, opts);   // the last block is usually shorter than the others
    if (!opts->quiet)
    {
        printf("\n");
    }
    print_summary(&a);
    return 0;
}

// Returns 0 on success, -1 on invalid options
static int parse_options(int argc, char *argv[], Options *opts)
{
    *opts = (Options) {.block_size = DEFAULT_BLOCK_SIZE};

    int opt;
    while ((opt = getopt(argc, argv, "qb:")) != -1)
    {
        switch (opt)
        {
            case 'q':
                opts->quiet = 1;
                break;
            case 'b':
                if (parse_size(optarg, 0, &opts->block_size) != 0 ||
                    opts->block_size < MIN_BLOCK_SIZE)
                {
                    fprintf(stderr, "Invalid block size (the minimum is %d): %s\n",
                            MIN_BLOCK_SIZE, optarg);
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

int cmd_entropy(int argc, char *argv[])
{
    Options opts;
    if (parse_options(argc, argv, &opts) != 0)
    {
        fprintf(stderr, "Usage: " COMMAND_NAME " [-q] [-b SIZE] [FILE]\n");
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
