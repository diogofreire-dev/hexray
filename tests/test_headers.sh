#!/usr/bin/env bash
# Checks `hexray headers` on ELF and PE files built byte by byte, valid and broken.
#
# Usage: tests/test_headers.sh path/to/hexray
#
# Written for bash 3.2, the version that ships with macOS. Needs python3 to build the
# fixtures. The most important results come from the sanitized build: on a broken
# file, this parser must report the damage and never read outside of the file.

set -u

if [ $# -ne 1 ] || [ ! -x "$1" ]; then
    echo "Usage: $0 path/to/hexray" >&2
    exit 2
fi

# Absolute paths, because the tests run from inside a temporary folder
hexray=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
tests_dir=$(cd "$(dirname "$0")" && pwd)
original=$1

work=$(mktemp -d "${TMPDIR:-/tmp}/hexray-tests.XXXXXX") || exit 2
trap 'rm -rf "$work"' EXIT
cd "$work" || exit 2

python3 "$tests_dir/make_headers_fixtures.py" "$work" || exit 2

passed=0
failed=0

pass() { passed=$((passed + 1)); }

fail() {
    failed=$((failed + 1))
    echo "FAIL: $1"
}

# Runs hexray, then fails the test if a sanitizer reported anything
run() {
    "$hexray" headers "$@" >output 2>errors
    status=$?
    if grep -Eq 'Sanitizer|runtime error' errors; then
        fail "memory error on: headers $*"
        head -20 errors | sed 's/^/  /'
        return 1
    fi
    return 0
}

# has_line LINE ARGUMENTS...  LINE must be one of the lines of the output
has_line() {
    local line=$1
    shift
    run "$@" || return
    if [ "$status" -eq 0 ] && grep -Fxq -- "$line" output; then
        pass
    else
        fail "headers $*: no line \"$line\" (exit code $status)"
        head -24 output errors | sed 's/^/  /'
    fi
}

# no_line LINE ARGUMENTS...  LINE must not appear in the output
no_line() {
    local line=$1
    shift
    run "$@" || return
    if grep -Fxq -- "$line" output; then
        fail "headers $*: unexpected line \"$line\""
    else
        pass
    fi
}

# fails REASON ARGUMENTS...  must exit with 1, print nothing and give that reason
fails() {
    local reason=$1
    shift
    run "$@" || return
    if [ "$status" -eq 1 ] && [ ! -s output ] && grep -Fq -- "$reason" errors; then
        pass
    else
        fail "headers $*: expected failure \"$reason\" (exit code $status)"
        head -6 output errors | sed 's/^/  /'
    fi
}

# survives FILE: any result is fine as long as it exits normally and cleanly
survives() {
    run "$1" || return
    if [ "$status" -eq 0 ] || [ "$status" -eq 1 ]; then
        pass
    else
        fail "headers $1: exit code $status"
    fi
}

HEADER='Name              Offset    Size      Entropy  Perms'
DAMAGED='Warning:  import table is damaged'
OUTSIDE='Warning:  a section points outside the file'
INJECTION='Warning:  imports match the classic code injection pattern'

# --- A valid PE -----------------------------------------------------------------

file=valid-pe64.exe
has_line "Format:   PE32+, x86-64" $file
has_line "Entry:    0x1234" $file
has_line "$HEADER" $file
has_line ".text             00000400  00000200  0.00     r-x" $file
has_line ".evil?[           00000a00  00000400  8.00     rwx  HIGH" $file
has_line "Imports:  7" $file
has_line "  KERNEL32.dll!VirtualAlloc" $file
has_line "  KERNEL32.dll!WriteProcessMemory  [INJECTION]" $file
has_line "  KERNEL32.dll!CreateRemoteThread  [INJECTION]" $file
has_line "  KERNEL32.dll!IsDebuggerPresent  [ANTI-ANALYSIS]" $file
has_line "  KERNEL32.dll!GetLastError" $file
has_line "  urlmon.dll!URLDownloadToFileA  [DOWNLOAD]" $file
has_line "  WS2_32.dll!#115" $file
has_line "Warning:  section .evil?[ is both writable and executable" $file
has_line "$INJECTION" $file
no_line "$DAMAGED" $file

# -f keeps only what is flagged, and the total stays the real one
has_line "Imports:  7" -f $file
has_line "  KERNEL32.dll!WriteProcessMemory  [INJECTION]" -f $file
no_line "  KERNEL32.dll!GetLastError" -f $file
no_line "  WS2_32.dll!#115" -f $file

# The same program in 32 bits, where the fields move and the entries are smaller
file=valid-pe32.exe
has_line "Format:   PE32, x86" $file
has_line "Entry:    0x1234" $file
has_line "Imports:  7" $file
has_line "  urlmon.dll!URLDownloadToFileA  [DOWNLOAD]" $file
has_line "  WS2_32.dll!#115" $file
has_line "$INJECTION" $file

# --- A valid ELF ----------------------------------------------------------------

file=valid-elf64
has_line "Format:   ELF64, x86-64, shared object or PIE, little-endian" $file
has_line "Entry:    0x1040" $file
has_line ".text             00000040  00000200  0.00     r-x" $file
has_line ".evil             00000240  00000400  8.00     rwx  HIGH" $file
has_line "Imports:  2" $file
has_line "  ptrace  [ANTI-ANALYSIS]" $file
has_line "  execve  [EXECUTION]" $file
no_line "  my_export" $file
has_line "Warning:  section .evil is both writable and executable" $file

# Memory only: it has no bytes in the file to measure
run $file
if grep -Eq '^\.bss +[0-9a-f]{8}  00000000  -        rw-$' output; then pass; else
    fail ".bss should have no size in the file and no entropy"; grep bss output; fi

file=valid-elf32-big
has_line "Format:   ELF32, MIPS, executable, big-endian" $file
has_line "Entry:    0x1040" $file
has_line "Imports:  2" $file
has_line "  ptrace  [ANTI-ANALYSIS]" $file

# --- Broken files: fatal --------------------------------------------------------

fails "has no valid PE header" pe-lfanew-outside
fails "has no valid PE header" pe-no-signature
fails "truncated or invalid PE header" pe-cut-in-coff
fails "truncated or invalid PE header" pe-bad-magic
fails "invalid ELF header" elf-bad-class
fails "invalid ELF header" elf-bad-encoding
fails "truncated ELF header" elf-cut-in-header

# --- Broken files: what could be read, plus a warning ---------------------------

has_line "Warning:  section table is truncated" pe-cut-in-sections
has_line "Warning:  too many sections: only the first ones are shown" pe-many-sections
has_line "Warning:  section table is truncated" pe-sections-past-end
has_line "$OUTSIDE" pe-section-outside
has_line "$DAMAGED" pe-import-rva-outside
has_line "$DAMAGED" pe-cut-in-imports
has_line "$DAMAGED" pe-cut-in-name
has_line "$DAMAGED" pe-no-terminator
survives pe-self-loop
has_line "Warning:  sections overlap too much: some entropy values are missing" pe-overlapping

has_line "Warning:  no usable section table (stripped or damaged)" elf-table-outside
has_line "Warning:  no usable section table (stripped or damaged)" elf-no-table
has_line "Warning:  no usable section table (stripped or damaged)" elf-entry-size-small
has_line "Sections: none" elf-no-table
has_line "Imports:  0" elf-no-table
has_line "Warning:  section table is truncated" elf-many-sections
has_line "(unknown)         00000040  00000200  0.00     r-x" elf-bad-names-index
has_line "Warning:  section table is truncated" elf-cut-in-table
has_line "$OUTSIDE" elf-section-outside
has_line "$DAMAGED" elf-symbols-outside
has_line "$DAMAGED" elf-symbols-huge
has_line "$DAMAGED" elf-bad-symbol-link
has_line "$DAMAGED" elf-strings-outside

# --- Random damage --------------------------------------------------------------

for file in fuzz/case-*; do
    survives "$file"
done

# Every possible cut of a small part of the header region
head -c 400 valid-pe64.exe >whole
length=1
while [ "$length" -lt 400 ]; do
    head -c "$length" whole >cut
    survives cut
    length=$((length + 13))
done

# --- Inputs and errors ----------------------------------------------------------

fails "not an ELF or PE file" /bin/ls
printf 'hello' >text
fails "not an ELF or PE file" text
: >empty
fails "not an ELF or PE file" empty
fails "No such file" missing.bin
mkdir folder
fails "" folder
fails "Usage" text empty
fails "Usage" -z text

actual=$("$hexray" headers <valid-pe64.exe | head -1)
if [ "$actual" = "Format:   PE32+, x86-64" ]; then pass; else fail "redirected stdin: $actual"; fi
actual=$(cat valid-elf64 | "$hexray" headers | head -1)
if [ "$actual" = "Format:   ELF64, x86-64, shared object or PIE, little-endian" ]; then pass; else
    fail "stdin through a pipe: $actual"; fi

echo "$original: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
