#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT_SIZE ((size_t) 1 << 30)
#define FIRST_BUFFER_SIZE ((size_t) 1 << 20)

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

void print_file_error(const char *command, const char *label, int error)
{
    fprintf(stderr, "%s: ", command);
    print_untrusted(stderr, label);
    fprintf(stderr, ": %s\n", strerror(error));
}

int read_all(FILE *in, const char *command, const char *label, unsigned char **out, size_t *out_size)
{
    size_t capacity = FIRST_BUFFER_SIZE;
    size_t size = 0;
    unsigned char *data = malloc(capacity);

    while (data != NULL)
    {
        size += fread(data + size, 1, capacity - size, in);
        if (size < capacity)
        {
            break;   // the input ended (or failed, checked below)
        }
        if (capacity >= MAX_INPUT_SIZE)
        {
            fprintf(stderr, "%s: ", command);
            print_untrusted(stderr, label);
            fprintf(stderr, ": file is too large (the limit is 1 GiB)\n");
            free(data);
            return -1;
        }
        capacity *= 2;
        unsigned char *grown = realloc(data, capacity);
        if (grown == NULL)
        {
            free(data);
        }
        data = grown;
    }

    if (data == NULL)
    {
        fprintf(stderr, "%s: out of memory\n", command);
        return -1;
    }
    if (ferror(in))
    {
        print_file_error(command, label, errno);
        free(data);
        return -1;
    }

    *out = data;
    *out_size = size;
    return 0;
}
