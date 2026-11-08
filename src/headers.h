// The `hexray headers` subcommand: lists the sections and imported functions of ELF
// and PE files, and flags the suspicious ones.

#ifndef HEXRAY_HEADERS_H
#define HEXRAY_HEADERS_H

// Runs the subcommand. argv[0] is "headers" and the options follow it.
// Returns the exit code for the program (0 = success).
int cmd_headers(int argc, char *argv[]);

#endif
