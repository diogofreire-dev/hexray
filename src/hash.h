// The `hexray hash` subcommand: prints the SHA-256 of files.

#ifndef HEXRAY_HASH_H
#define HEXRAY_HASH_H

// Runs the subcommand. argv[0] is "hash" and the file names follow it.
// Returns the exit code for the program (0 = every file could be read).
int cmd_hash(int argc, char *argv[]);

#endif
