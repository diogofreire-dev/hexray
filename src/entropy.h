// The `hexray entropy` subcommand: measures how random a file's bytes are, to spot
// content that is packed, compressed or encrypted.

#ifndef HEXRAY_ENTROPY_H
#define HEXRAY_ENTROPY_H

#include <stddef.h>   // for size_t

// Runs the subcommand. argv[0] is "entropy" and the options follow it.
// Returns the exit code for the program (0 = success).
int cmd_entropy(int argc, char *argv[]);

// Above this many bits per byte, data looks compressed or encrypted
#define HIGH_ENTROPY 7.2

// Returns the Shannon entropy of a piece of data, from 0 to 8
double entropy_of_bytes(const unsigned char *data, size_t length);

#endif
