// hexray scan: searches files for byte patterns, the idea behind antivirus signatures
// and YARA, the standard tool of malware analysts.
//
// Usage: hexray scan -r RULES [FILE...]
//   Without FILE, reads standard input.
//
// A rules file has one rule per line, and # starts a comment:
//
//   upx_magic: 55 50 58 21
//   pe_x86_64: 50 45 00 00 64 86
//   with_gap:  4d 5a ?? ?? 03
//
// Each byte is two hex digits, and ?? means "any byte here". Wildcards matter because
// malware variants change small details, such as an address, around the same code.

// getopt and getline are POSIX, not standard C (see the same line in dump.c)
#define _POSIX_C_SOURCE 200809L

#include "scan.h"
#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define COMMAND_NAME "hexray scan"
#define MAX_RULE_NAME 64
#define MAX_PATTERN_LENGTH 4096
#define WILDCARD (-1)
#define BYTE_VALUES 256

typedef struct
{
    char name[MAX_RULE_NAME];
    // One element per byte of the pattern: 0 to 255, or WILDCARD. A plain byte could
    // not do this, since every one of its 256 values already means a real byte.
    int16_t *pattern;
    size_t length;
} Rule;

typedef struct
{
    Rule *rules;
    size_t count;
    size_t capacity;
} RuleSet;

static void rules_free(RuleSet *set)
{
    for (size_t i = 0; i < set->count; i++)
    {
        free(set->rules[i].pattern);
    }
    free(set->rules);
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f')
    {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F')
    {
        return c - 'A' + 10;
    }
    return -1;
}

// Removes spaces from both ends. Writing the '\0' cuts the end in place, and the
// returned pointer skips the start: the text is never moved.
static char *trim(char *text)
{
    while (isspace((unsigned char) *text))
    {
        text++;
    }

    size_t length = strlen(text);
    while (length > 0 && isspace((unsigned char) text[length - 1]))
    {
        text[--length] = '\0';
    }
    return text;
}

static const char *check_name(const char *name, const RuleSet *set)
{
    size_t length = strlen(name);
    if (length == 0 || length >= MAX_RULE_NAME)
    {
        return "the rule name must have between 1 and 63 characters";
    }

    for (size_t i = 0; i < length; i++)
    {
        unsigned char c = (unsigned char) name[i];
        if (!isalnum(c) && c != '_' && c != '-' && c != '.')
        {
            return "the rule name can only use letters, digits, _ - and .";
        }
    }

    for (size_t i = 0; i < set->count; i++)
    {
        if (strcmp(set->rules[i].name, name) == 0)
        {
            return "another rule already has this name";
        }
    }
    return NULL;
}

// Turns the text of a pattern into a new array. Returns NULL if it is valid, or the
// reason why it is not. On success the caller owns *out and must free it.
static const char *parse_pattern(const char *text, int16_t **out, size_t *out_length)
{
    // Two digits per byte, so this is enough room however the bytes are spaced
    int16_t *pattern = malloc((strlen(text) / 2 + 1) * sizeof(int16_t));
    if (pattern == NULL)
    {
        return "out of memory";
    }

    const char *error = NULL;
    size_t length = 0;
    int has_real_byte = 0;

    while (*text != '\0' && error == NULL)
    {
        if (isspace((unsigned char) *text))
        {
            text++;
            continue;
        }

        int high = hex_value(text[0]);
        int low = text[1] != '\0' ? hex_value(text[1]) : -1;   // text[1] may be the end

        if (text[0] == '?' && text[1] == '?')
        {
            pattern[length++] = WILDCARD;
        }
        else if (high >= 0 && low >= 0)
        {
            pattern[length++] = (int16_t) (high << 4 | low);
            has_real_byte = 1;
        }
        else
        {
            error = "each byte must be two hex digits, or ??";
            break;
        }
        text += 2;
    }

    if (error == NULL && length == 0)
    {
        error = "the pattern is empty";
    }
    else if (error == NULL && length > MAX_PATTERN_LENGTH)
    {
        error = "the pattern is too long (the limit is 4096 bytes)";
    }
    else if (error == NULL && !has_real_byte)
    {
        error = "a pattern with only ?? would match everything";   // and has nothing to search for
    }

    if (error != NULL)
    {
        free(pattern);
        return error;
    }

    *out = pattern;
    *out_length = length;
    return NULL;
}

// Adds the rule on this line, if there is one. Returns NULL or the reason it is invalid.
static const char *parse_line(char *line, RuleSet *set)
{
    char *comment = strchr(line, '#');
    if (comment != NULL)
    {
        *comment = '\0';
    }

    char *text = trim(line);
    if (*text == '\0')
    {
        return NULL;   // a blank line or only a comment
    }

    char *colon = strchr(text, ':');
    if (colon == NULL)
    {
        return "expected  name: hex pattern";
    }
    *colon = '\0';   // now `text` ends at the name, and the pattern starts after the colon

    const char *name = trim(text);
    const char *error = check_name(name, set);
    if (error != NULL)
    {
        return error;
    }

    int16_t *pattern;
    size_t length;
    error = parse_pattern(colon + 1, &pattern, &length);
    if (error != NULL)
    {
        return error;
    }

    if (set->count == set->capacity)
    {
        size_t capacity = set->capacity == 0 ? 32 : set->capacity * 2;
        Rule *grown = realloc(set->rules, capacity * sizeof(Rule));
        if (grown == NULL)
        {
            free(pattern);
            return "out of memory";
        }
        set->rules = grown;
        set->capacity = capacity;
    }

    Rule *rule = &set->rules[set->count++];
    strcpy(rule->name, name);   // safe: check_name already confirmed that it fits
    rule->pattern = pattern;
    rule->length = length;
    return NULL;
}

// Returns 0 on success, -1 on failure (already reported)
static int load_rules(const char *path, RuleSet *set)
{
    FILE *file = fopen(path, "r");
    if (file == NULL)
    {
        print_file_error(COMMAND_NAME, path, errno);
        return -1;
    }

    // getline allocates and grows `line` for us, so a line can have any length.
    // The same buffer is reused on each call and freed once at the end.
    char *line = NULL;
    size_t capacity = 0;
    unsigned long line_number = 0;
    int status = 0;

    while (status == 0 && getline(&line, &capacity, file) != -1)
    {
        line_number++;
        const char *error = parse_line(line, set);
        if (error != NULL)
        {
            fprintf(stderr, COMMAND_NAME ": ");
            print_untrusted(stderr, path);
            fprintf(stderr, ":%lu: %s\n", line_number, error);
            status = -1;
        }
    }

    if (status == 0 && ferror(file))
    {
        print_file_error(COMMAND_NAME, path, errno);
        status = -1;
    }
    if (status == 0 && set->count == 0)
    {
        fprintf(stderr, COMMAND_NAME ": ");
        print_untrusted(stderr, path);
        fprintf(stderr, ": the file has no rules\n");
        status = -1;
    }

    free(line);
    fclose(file);
    return status;
}

static int matches_at(const Rule *rule, const unsigned char *data)
{
    for (size_t i = 0; i < rule->length; i++)
    {
        if (rule->pattern[i] != WILDCARD && rule->pattern[i] != data[i])
        {
            return 0;
        }
    }
    return 1;
}

// Finds the first match. Returns 1 and sets *offset, or returns 0 if there is none.
//
// Trying every position would be slow on a sample full of the byte a pattern starts
// with. So we search only for the byte of the pattern that is rarest in this file, and
// compare the whole pattern just where that byte appears. A file that does not
// contain it at all is ruled out at once.
static int find_rule(const Rule *rule, const unsigned char *data, size_t size,
                     const unsigned long long counts[], size_t *offset)
{
    if (rule->length > size)
    {
        return 0;
    }

    size_t anchor = SIZE_MAX;
    for (size_t i = 0; i < rule->length; i++)
    {
        if (rule->pattern[i] != WILDCARD &&
            (anchor == SIZE_MAX || counts[rule->pattern[i]] < counts[rule->pattern[anchor]]))
        {
            anchor = i;
        }
    }
    // A pattern always has a real byte (parse_pattern checked), so anchor is valid
    if (counts[rule->pattern[anchor]] == 0)
    {
        return 0;
    }

    // The anchor's position in the file, for each place the whole pattern fits
    const unsigned char *first = data + anchor;
    size_t positions = size - rule->length + 1;
    size_t start = 0;

    while (start < positions)
    {
        const unsigned char *hit = memchr(first + start, rule->pattern[anchor], positions - start);
        if (hit == NULL)
        {
            return 0;
        }

        size_t candidate = (size_t) (hit - first);
        if (matches_at(rule, data + candidate))
        {
            *offset = candidate;
            return 1;
        }
        start = candidate + 1;
    }
    return 0;
}

// Returns 0 on success, -1 on a read error (already reported)
static int scan_stream(FILE *in, const char *label, const RuleSet *set)
{
    unsigned char *data;
    size_t size;
    if (read_all(in, COMMAND_NAME, label, &data, &size) != 0)
    {
        return -1;
    }

    unsigned long long counts[BYTE_VALUES] = {0};
    for (size_t i = 0; i < size; i++)
    {
        counts[data[i]]++;
    }

    int matched = 0;
    for (size_t i = 0; i < set->count; i++)
    {
        size_t offset;
        if (find_rule(&set->rules[i], data, size, counts, &offset))
        {
            print_untrusted(stdout, label);
            printf(": %s at 0x%zx\n", set->rules[i].name, offset);
            matched = 1;
        }
    }

    if (!matched)
    {
        print_untrusted(stdout, label);
        printf(": no rules matched\n");
    }

    free(data);
    return 0;
}

int cmd_scan(int argc, char *argv[])
{
    const char *rules_path = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "r:")) != -1)
    {
        if (opt != 'r')
        {
            rules_path = NULL;   // getopt already printed what was wrong
            break;
        }
        rules_path = optarg;
    }

    if (rules_path == NULL)
    {
        fprintf(stderr, "Usage: " COMMAND_NAME " -r RULES [FILE...]\n");
        return 1;
    }

    RuleSet set = {0};
    if (load_rules(rules_path, &set) != 0)
    {
        rules_free(&set);
        return 1;
    }

    int status = 0;
    if (optind == argc)
    {
        status = scan_stream(stdin, "(stdin)", &set) == 0 ? 0 : 1;
    }

    // One unreadable file must not stop the others
    for (int i = optind; i < argc; i++)
    {
        FILE *in = fopen(argv[i], "rb");   // read only: samples are never executed
        if (in == NULL)
        {
            print_file_error(COMMAND_NAME, argv[i], errno);
            status = 1;
            continue;
        }
        if (scan_stream(in, argv[i], &set) != 0)
        {
            status = 1;
        }
        fclose(in);
    }

    rules_free(&set);
    return status;
}
