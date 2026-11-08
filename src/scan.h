// The `hexray scan` subcommand: searches files for byte patterns read from a rules file.

#ifndef HEXRAY_SCAN_H
#define HEXRAY_SCAN_H

// Runs the subcommand. argv[0] is "scan" and the options follow it.
// Returns the exit code for the program (0 = the rules and every file could be read).
int cmd_scan(int argc, char *argv[]);

#endif
