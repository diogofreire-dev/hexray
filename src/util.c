#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

int parse_size(const char *text, int base, unsigned long long *out)
{
    char *end;
    errno = 0;
    unsigned long long value = strtoull(text, &end, base);
    // strtoull accepts "-1" and turns it into a huge number, so reject any minus sign
    // by hand (strchr, not text[0], because strtoull also skips leading spaces)
    if (end == text || *end != '\0' || errno == ERANGE || strchr(text, '-') != NULL)
    {
        return -1;
    }
    *out = value;
    return 0;
}

// A file name is untrusted input too: it can contain terminal escape sequences that
// recolour or rewrite what the analyst sees. Bytes above 127 are kept, so names with
// accents still read correctly. The cast is needed because ctype functions are
// undefined for negative values, and a plain char can be negative.
void print_untrusted(FILE *out, const char *text)
{
    for (; *text != '\0'; text++)
    {
        fputc(iscntrl((unsigned char) *text) ? '?' : *text, out);
    }
}
