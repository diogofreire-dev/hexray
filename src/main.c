// hexray: a static malware triage tool. It reads files and never executes them.
//
// This file only decides which subcommand to run. Each subcommand lives in its own
// .c/.h pair, so adding one later means writing it and adding a line to `commands`.

#include "dump.h"

#include <stdio.h>
#include <string.h>

// One entry per subcommand. `run` is a function pointer: a variable that holds the
// address of a function, so the table can say which function goes with each name.
// Every subcommand must have this exact signature for that to work.
typedef struct
{
    const char *name;
    int (*run)(int argc, char *argv[]);
    const char *summary;
} Command;

static const Command commands[] = {
    {"dump", cmd_dump, "show the bytes of a file (same output as hexdump -C)"},
};

// sizeof(whole array) / sizeof(one element) = number of elements. It only works
// here, where the compiler can still see the real array and not just a pointer.
static const size_t command_count = sizeof(commands) / sizeof(commands[0]);

// Takes the stream because help goes to stdout when asked for and to stderr on errors
static void usage(FILE *out)
{
    fprintf(out, "Usage: hexray COMMAND [OPTIONS] [FILE]\n\nCommands:\n");
    for (size_t i = 0; i < command_count; i++)
    {
        fprintf(out, "  %-10s %s\n", commands[i].name, commands[i].summary);
    }
    fprintf(out, "\nhexray only reads the files it analyses. It never executes them.\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        usage(stderr);
        return 1;
    }

    const char *name = argv[1];
    if (strcmp(name, "help") == 0 || strcmp(name, "-h") == 0 || strcmp(name, "--help") == 0)
    {
        usage(stdout);
        return 0;
    }

    for (size_t i = 0; i < command_count; i++)
    {
        if (strcmp(name, commands[i].name) == 0)
        {
            // argv + 1 is pointer arithmetic: the subcommand receives an argv that
            // starts at its own name, so it can use getopt as if it were a program.
            return commands[i].run(argc - 1, argv + 1);
        }
    }

    fprintf(stderr, "hexray: unknown command: %s\n\n", name);
    usage(stderr);
    return 1;
}
