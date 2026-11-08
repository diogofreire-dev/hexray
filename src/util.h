// Small helpers shared by more than one subcommand.

#ifndef HEXRAY_UTIL_H
#define HEXRAY_UTIL_H

#include <stdio.h>

// Converts text to a number. Base 10 accepts only decimal; base 0 also accepts hex
// (0x10) and octal (020). Returns 0 on success, -1 if the text is not a valid number.
int parse_size(const char *text, int base, unsigned long long *out);

// Prints text that came from outside the program, with control characters as '?'.
void print_untrusted(FILE *out, const char *text);

// Prints "command: label: reason" on stderr. `error` is a value of errno.
void print_file_error(const char *command, const char *label, int error);

// Reads a whole input into memory, up to 1 GiB. The caller must free *out.
// Returns 0 on success, -1 on failure (already reported).
int read_all(FILE *in, const char *command, const char *label, unsigned char **out, size_t *out_size);

#endif
