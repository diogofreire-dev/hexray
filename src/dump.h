// The `hexray dump` subcommand: shows the bytes of a file like `hexdump -C`.
//
// A header (.h) is the public face of a .c file: it declares what other files may
// call, while the code itself stays in the .c. main.c only needs to know that
// cmd_dump exists and what it looks like; the linker joins the two files later.

// Include guard: if this header ends up included twice in the same .c file, the
// second copy is skipped, so nothing gets declared twice.
#ifndef HEXRAY_DUMP_H
#define HEXRAY_DUMP_H

// Runs the subcommand. argv[0] is "dump" and the options follow it, the same shape
// a normal main() receives. Returns the exit code for the program (0 = success).
int cmd_dump(int argc, char *argv[]);

#endif
