// Small helpers shared by more than one subcommand.

#ifndef HEXRAY_UTIL_H
#define HEXRAY_UTIL_H

#include <stdio.h>

// Converts text to a number. Base 10 accepts only decimal; base 0 also accepts hex
// (0x10) and octal (020). Returns 0 on success, -1 if the text is not a valid number.
int parse_size(const char *text, int base, unsigned long long *out);

// Prints text that came from outside the program, with control characters as '?'.
void print_untrusted(FILE *out, const char *text);

#endif
