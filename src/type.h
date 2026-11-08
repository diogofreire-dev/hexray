// The `hexray type` subcommand: identifies a file by its first bytes (magic bytes)
// and flags files whose extension does not match their content.

#ifndef HEXRAY_TYPE_H
#define HEXRAY_TYPE_H

// Runs the subcommand. argv[0] is "type" and the options follow it.
// Returns the exit code for the program (0 = every file could be read).
int cmd_type(int argc, char *argv[]);

#endif
