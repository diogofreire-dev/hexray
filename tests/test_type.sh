#!/usr/bin/env bash
# Checks the output and exit code of `hexray type` on files built byte by byte.
#
# Usage: tests/test_type.sh path/to/hexray
#
# Written for bash 3.2, the version that ships with macOS. The fixtures only contain
# signatures, so they are harmless: none of them is a working program.

set -u

if [ $# -ne 1 ] || [ ! -x "$1" ]; then
    echo "Usage: $0 path/to/hexray" >&2
    exit 2
fi

# An absolute path, because the tests run from inside the fixtures folder
hexray=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
original=$1

work=$(mktemp -d "${TMPDIR:-/tmp}/hexray-tests.XXXXXX") || exit 2
trap 'rm -rf "$work"' EXIT
cd "$work" || exit 2

passed=0
failed=0

PE="Windows executable (PE)"
ELF="Linux executable (ELF)"
MACHO="macOS executable (Mach-O 64-bit)"
UNIVERSAL="macOS universal binary"
JAVA="Java class file"
ZIP="ZIP archive"
OLE="Old Office document (OLE2)"
PDF="PDF document"
PNG="PNG image"
JPEG="JPEG image"
UNKNOWN="Unknown (no known signature)"

# Magic bytes, as printf formats (\x25 is %, which printf would otherwise interpret)
MAGIC_PE='MZ\x90\x00'
MAGIC_ELF='\x7fELF\x02\x01\x01\x00'
MAGIC_MACHO='\xcf\xfa\xed\xfe\x0c\x00\x00\x01'
MAGIC_UNIVERSAL='\xca\xfe\xba\xbe\x00\x00\x00\x02'
MAGIC_JAVA='\xca\xfe\xba\xbe\x00\x00\x00\x34'
MAGIC_ZIP='PK\x03\x04\x14\x00'
MAGIC_OLE='\xd0\xcf\x11\xe0\xa1\xb1'
MAGIC_PDF='\x25PDF-1.7'
MAGIC_PNG='\x89PNG\r\n'
MAGIC_JPEG='\xff\xd8\xff\xe0'
MAGIC_NONE='hello there'

# expect STATUS OUTPUT ARGUMENTS...  compares against what `hexray type ARGUMENTS` does
expect() {
    local status=$1 output=$2 actual actual_status
    shift 2
    actual=$("$hexray" type "$@" 2>errors)
    actual_status=$?
    # A failure must always say why on stderr
    if [ "$actual_status" -eq "$status" ] && [ "$actual" = "$output" ] &&
        { [ "$status" -eq 0 ] || [ -s errors ]; }; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
        echo "FAIL: type $*"
        echo "  expected ($status): $output"
        echo "  actual ($actual_status): $actual"
        head -6 errors | sed 's/^/  /'
    fi
}

# has_type NAME MAGIC EXPECTED_TYPE: creates the file and expects no mismatch
has_type() {
    printf "$2" >"$1"
    expect 0 "$1: $3" "$1"
}

# is_fake NAME MAGIC EXPECTED_TYPE CLAIMED_TYPE: creates the file and expects a mismatch
is_fake() {
    local extension=${1##*.}
    printf "$2" >"$1"
    expect 0 "$1: $3  [MISMATCH: .$extension is the extension of: $4]" "$1"
}

# Every format, with a name that matches
has_type program.exe "$MAGIC_PE" "$PE"
has_type library.dll "$MAGIC_PE" "$PE"
has_type program.elf "$MAGIC_ELF" "$ELF"
has_type library.so "$MAGIC_ELF" "$ELF"
has_type library.dylib "$MAGIC_MACHO" "$MACHO"
has_type fat.dylib "$MAGIC_UNIVERSAL" "$UNIVERSAL"
has_type Main.class "$MAGIC_JAVA" "$JAVA"
has_type archive.zip "$MAGIC_ZIP" "$ZIP"
has_type report.docx "$MAGIC_ZIP" "$ZIP"
has_type old.doc "$MAGIC_OLE" "$OLE"
has_type paper.pdf "$MAGIC_PDF" "$PDF"
has_type image.png "$MAGIC_PNG" "$PNG"
has_type photo.jpg "$MAGIC_JPEG" "$JPEG"
has_type photo.jpeg "$MAGIC_JPEG" "$JPEG"

# Disguises
is_fake invoice.pdf "$MAGIC_PE" "$PE" "$PDF"
is_fake notes.txt "$MAGIC_PE" "$PE" "Text file"
is_fake holiday.jpg "$MAGIC_ELF" "$ELF" "$JPEG"
is_fake setup.exe "$MAGIC_ZIP" "$ZIP" "$PE"
is_fake picture.png "$MAGIC_JPEG" "$JPEG" "$PNG"
is_fake INVOICE.PDF "$MAGIC_PE" "$PE" "$PDF"
is_fake broken.pdf "$MAGIC_NONE" "$UNKNOWN" "$PDF"
is_fake double.pdf.txt "$MAGIC_PE" "$PE" "Text file"

# Upper case extensions that do match
has_type SETUP.EXE "$MAGIC_PE" "$PE"

# Nothing to flag: no extension, unknown extension, text without a signature
has_type noextension "$MAGIC_PE" "$PE"
has_type backup.bak "$MAGIC_PE" "$PE"
has_type libc.so.6 "$MAGIC_ELF" "$ELF"
has_type readme.txt "$MAGIC_NONE" "$UNKNOWN"
has_type .bashrc "$MAGIC_PE" "$PE"
has_type trailingdot. "$MAGIC_PE" "$PE"

# A dot in the folder name is not an extension
mkdir folder.pdf
has_type folder.pdf/program "$MAGIC_PE" "$PE"

# Too short to match anything, and truncated signatures
has_type one-byte 'M' "$UNKNOWN"
has_type truncated-png '\x89PN' "$UNKNOWN"
has_type cafebabe-only '\xca\xfe\xba\xbe' "$UNKNOWN"

# Empty files: no content, so no mismatch either
: >empty
: >empty.pdf
expect 0 "empty: empty file" empty
expect 0 "empty.pdf: empty file" empty.pdf

# Several files at once, and a missing one must not stop the others
expect 0 "$(printf 'paper.pdf: %s\nprogram.exe: %s' "$PDF" "$PE")" paper.pdf program.exe
expect 1 "$(printf 'paper.pdf: %s\nprogram.exe: %s' "$PDF" "$PE")" paper.pdf missing.bin program.exe

# Errors must exit with 1 and explain why
expect 1 "" missing.bin
expect 1 "" folder.pdf
expect 1 "" -z paper.pdf

# A file whose name starts with a dash
printf "$MAGIC_PE" >./-dash.exe
expect 0 "-dash.exe: $PE" -- -dash.exe

# Terminal escape sequences in a file name must not reach the screen
escape_name=$(printf 'evil\033[31m.exe')
printf "$MAGIC_PE" >"$escape_name"
expect 0 "evil?[31m.exe: $PE" "$escape_name"

# Accents are not control characters and must survive
printf "$MAGIC_PDF" >"março.pdf"
expect 0 "março.pdf: $PDF" "março.pdf"

# Standard input has no name, so no extension to compare
actual=$("$hexray" type <invoice.pdf)
if [ "$actual" = "(stdin): $PE" ]; then passed=$((passed + 1)); else
    failed=$((failed + 1)); echo "FAIL: redirected stdin: $actual"; fi

actual=$(cat paper.pdf | "$hexray" type)
if [ "$actual" = "(stdin): $PDF" ]; then passed=$((passed + 1)); else
    failed=$((failed + 1)); echo "FAIL: stdin through a pipe: $actual"; fi

# Real binaries from this machine
if [ "$(uname)" = "Darwin" ]; then
    expect 0 "/bin/ls: $UNIVERSAL" /bin/ls
    expect 0 "$hexray: $MACHO" "$hexray"
fi

echo "$original: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
