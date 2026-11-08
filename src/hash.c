// hexray hash: prints the SHA-256 of files, in the same format as `shasum -a 256`.
//
// Usage: hexray hash [FILE...]
//   Without FILE, reads standard input (shown as "-").
//
// A hash works as a fingerprint of a file. Searching it on VirusTotal or MalwareBazaar
// shows whether the file is already known as malware, without uploading the file.

// getopt is POSIX, not standard C (see the same line in dump.c)
#define _POSIX_C_SOURCE 200809L

#include "hash.h"
#include "sha256.h"
#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#define COMMAND_NAME "hexray hash"
#define READ_SIZE 65536

// Prints the hash of one input. Returns 0 on success, -1 on a read error.
static int hash_stream(FILE *in, const char *label)
{
    Sha256 sha;
    unsigned char buffer[READ_SIZE];
    size_t got;

    sha256_init(&sha);
    while ((got = fread(buffer, 1, sizeof(buffer), in)) > 0)
    {
        sha256_update(&sha, buffer, got);
    }

    if (ferror(in))
    {
        print_file_error(COMMAND_NAME, label, errno);
        return -1;
    }

    unsigned char digest[SHA256_DIGEST_SIZE];
    sha256_final(&sha, digest);

    for (int i = 0; i < SHA256_DIGEST_SIZE; i++)
    {
        printf("%02x", digest[i]);
    }
    printf("  ");
    print_untrusted(stdout, label);
    printf("\n");
    return 0;
}

int cmd_hash(int argc, char *argv[])
{
    // No options exist. Calling getopt rejects a mistyped -x and handles `--`.
    if (getopt(argc, argv, "") != -1)
    {
        fprintf(stderr, "Usage: " COMMAND_NAME " [FILE...]\n");
        return 1;
    }

    if (optind == argc)
    {
        return hash_stream(stdin, "-") == 0 ? 0 : 1;
    }

    // One unreadable file must not stop the others
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
        if (hash_stream(in, argv[i]) != 0)
        {
            status = 1;
        }
        fclose(in);
    }
    return status;
}
