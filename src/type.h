// The `hexray type` subcommand: identifies a file by its first bytes (magic bytes)
// and flags files whose extension does not match their content.

#ifndef HEXRAY_TYPE_H
#define HEXRAY_TYPE_H

#include <stddef.h>   // for size_t

// Runs the subcommand. argv[0] is "type" and the options follow it.
// Returns the exit code for the program (0 = every file could be read).
int cmd_type(int argc, char *argv[]);

// How many bytes from the start of a file type_identify needs to see
#define TYPE_HEADER_SIZE 8

// Identifies a format from the first bytes of a file, for other subcommands to use.
// Returns its name, or NULL if unknown. Sets *is_executable to 1 for native programs.
const char *type_identify(const unsigned char *header, size_t length, int *is_executable);

#endif
