// The `hexray strings` subcommand: extracts readable text from any file and flags
// the strings that deserve an analyst's attention.
//
// This file is not called strings.h on purpose: the C library already has a header
// with that name, and sharing it would make it easy to include the wrong one.

#ifndef HEXRAY_STRSCAN_H
#define HEXRAY_STRSCAN_H

// Runs the subcommand. argv[0] is "strings" and the options follow it.
// Returns the exit code for the program (0 = success).
int cmd_strings(int argc, char *argv[]);

#endif
