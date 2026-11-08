// The `hexray entropy` subcommand: measures how random a file's bytes are, to spot
// content that is packed, compressed or encrypted.

#ifndef HEXRAY_ENTROPY_H
#define HEXRAY_ENTROPY_H

// Runs the subcommand. argv[0] is "entropy" and the options follow it.
// Returns the exit code for the program (0 = success).
int cmd_entropy(int argc, char *argv[]);

#endif
