#!/usr/bin/env bash
# Checks the output and exit code of `hexray entropy` on files with known entropy.
#
# Usage: tests/test_entropy.sh path/to/hexray
#
# Written for bash 3.2, the version that ships with macOS. The fixtures only contain
# signatures and filler bytes, so they are harmless: none of them is a working program.

set -u

if [ $# -ne 1 ] || [ ! -x "$1" ]; then
    echo "Usage: $0 path/to/hexray" >&2
    exit 2
fi

# An absolute path, because the tests run from inside a temporary folder
hexray=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
original=$1

work=$(mktemp -d "${TMPDIR:-/tmp}/hexray-tests.XXXXXX") || exit 2
trap 'rm -rf "$work"' EXIT
cd "$work" || exit 2

passed=0
failed=0

pass() { passed=$((passed + 1)); }

fail() {
    failed=$((failed + 1))
    echo "FAIL: $1"
}

# expect STATUS OUTPUT ARGUMENTS...  compares the whole output
expect() {
    local status=$1 output=$2 actual actual_status
    shift 2
    actual=$("$hexray" entropy "$@" 2>errors)
    actual_status=$?
    if [ "$actual_status" -eq "$status" ] && [ "$actual" = "$output" ] &&
        { [ "$status" -eq 0 ] || [ -s errors ]; }; then
        pass
    else
        fail "entropy $*"
        echo "  expected ($status): $output"
        echo "  actual ($actual_status): $actual"
        head -6 errors | sed 's/^/  /'
    fi
}

# has_line LINE ARGUMENTS...  LINE must be one of the lines of the output
has_line() {
    local line=$1 status
    shift
    "$hexray" entropy "$@" >output 2>errors
    status=$?
    if [ "$status" -eq 0 ] && grep -Fxq -- "$line" output; then
        pass
    else
        fail "entropy $*: no line \"$line\" (exit code $status)"
        head -12 output errors | sed 's/^/  /'
    fi
}

# no_line LINE ARGUMENTS...  LINE must not appear in the output
no_line() {
    local line=$1
    shift
    "$hexray" entropy "$@" >output 2>errors
    if grep -Fxq -- "$line" output; then
        fail "entropy $*: unexpected line \"$line\""
    else
        pass
    fi
}

BAR_EMPTY='................................'
BAR_FULL='################################'
PACKED='Verdict:  PACKED? Most of this executable is high entropy'
ENCRYPTED='Verdict:  ENCRYPTED? High entropy and no known file type (or compressed data)'
FORMAT='Verdict:  High entropy, which is common in this format'
NORMAL='Verdict:  No sign of packing or encryption'
BY_HAND='Verdict:  Packer signature found, but the entropy is normal: check it by hand'
SMALL='Verdict:  Too small to judge'

# --- Files with a known entropy -------------------------------------------------

# Every byte value once: exactly 8 bits. Repeated 16 times: still 8, in 4096 bytes.
for high in 0 1 2 3 4 5 6 7 8 9 a b c d e f; do
    for low in 0 1 2 3 4 5 6 7 8 9 a b c d e f; do
        printf "\\x$high$low"
    done
done >all-bytes
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do cat all-bytes; done >uniform

head -c 4096 /dev/zero >zeros

# Two values, equally frequent: exactly 1 bit
{ head -c 2048 /dev/zero | tr '\000' 'a'; head -c 2048 /dev/zero | tr '\000' 'b'; } >two-values

# --- Whole output ---------------------------------------------------------------

expect 0 "Offset    Entropy  0 to 8
00000000  0.00     $BAR_EMPTY

Type:     Unknown (no known signature)
Size:     4096 bytes
Entropy:  0.00 of 8.00
High:     0% of the file (blocks above 7.20)
Packer:   no known signature
$NORMAL" zeros

expect 0 "Offset    Entropy  0 to 8
00000000  8.00     $BAR_FULL  HIGH

Type:     Unknown (no known signature)
Size:     4096 bytes
Entropy:  8.00 of 8.00
High:     100% of the file (blocks above 7.20)
Packer:   no known signature
$ENCRYPTED" uniform

expect 0 "Type:     Unknown (no known signature)
Size:     4096 bytes
Entropy:  0.00 of 8.00
High:     0% of the file (blocks above 7.20)
Packer:   no known signature
$NORMAL" -q zeros

expect 0 "Empty input: nothing to measure" /dev/null

# --- The measurement ------------------------------------------------------------

has_line "00000000  1.00     ####............................" two-values
has_line "Entropy:  1.00 of 8.00" two-values
has_line "Entropy:  8.00 of 8.00" -q all-bytes

# Blocks: offsets, a custom size, a short last block
cat zeros uniform >mixed
has_line "00000000  0.00     $BAR_EMPTY" mixed
has_line "00001000  8.00     $BAR_FULL  HIGH" mixed
has_line "High:     50% of the file (blocks above 7.20)" mixed
has_line "00000800  0.00     $BAR_EMPTY" -b 2048 mixed
has_line "00000800  0.00     $BAR_EMPTY" -b 0x800 mixed
has_line "00001800  8.00     $BAR_FULL  HIGH" -b 2048 mixed
{ cat zeros; printf 'x'; } >short-tail
has_line "00001000  0.00     $BAR_EMPTY" short-tail
has_line "Size:     4097 bytes" short-tail

# Blocks larger than one read of the file
head -c 200000 /dev/zero >long-zeros
has_line "00000000  0.00     $BAR_EMPTY" -b 100000 long-zeros
has_line "00018000  0.00     $BAR_EMPTY" -b 0x18000 long-zeros
no_line "00010000  0.00     $BAR_EMPTY" -b 100000 long-zeros

# --- Verdicts -------------------------------------------------------------------

# with_magic MAGIC NAME: a file with those first bytes and nearly all high entropy
with_magic() {
    { printf "$1"; cat uniform uniform; } >"$2"
}

# A PE signature needs its real header: "MZ", then at 0x3c the offset of "PE\0\0"
with_magic "MZ$(printf '\\x00%.0s' {1..58})\\x40\\x00\\x00\\x00PE\\x00\\x00" fake-pe
has_line "Type:     Windows executable (PE)" fake-pe
has_line "$PACKED" fake-pe
with_magic '\x7fELF\x02\x01\x01\x00' fake-elf
has_line "$PACKED" fake-elf
with_magic '\xcf\xfa\xed\xfe\x0c\x00\x00\x01' fake-macho
has_line "$PACKED" fake-macho
with_magic '\xca\xfe\xba\xbe\x00\x00\x00\x02' fake-universal
has_line "$PACKED" fake-universal

# Compressed formats are high entropy by design and must not be accused of anything
with_magic 'PK\x03\x04' fake-zip
has_line "$FORMAT" fake-zip
with_magic '\xff\xd8\xff\xe0' fake-jpeg
has_line "$FORMAT" fake-jpeg
with_magic '\x89PNG' fake-png
has_line "$FORMAT" fake-png
with_magic '\xca\xfe\xba\xbe\x00\x00\x00\x34' fake-java
has_line "$FORMAT" fake-java

# An executable with normal entropy
{ printf 'MZ'; head -c 8192 /dev/zero; } >plain-pe
has_line "$NORMAL" plain-pe

# The 70% line: 3 high blocks out of 4 is packed, 2 out of 4 is not
{ printf 'MZ'; tail -c 4094 uniform; cat uniform uniform zeros; } >three-of-four
has_line "High:     75% of the file (blocks above 7.20)" three-of-four
has_line "$PACKED" three-of-four
{ printf 'MZ'; tail -c 4094 uniform; cat uniform zeros zeros; } >two-of-four
has_line "High:     50% of the file (blocks above 7.20)" two-of-four
has_line "$NORMAL" two-of-four

# Too little data to say anything
printf 'MZ' >tiny
has_line "$SMALL" tiny
head -c 1023 uniform >almost
has_line "$SMALL" almost
head -c 1024 uniform >enough
has_line "$ENCRYPTED" enough

# --- Packer signatures ----------------------------------------------------------

{ printf 'MZ'; head -c 100 /dev/zero; printf 'UPX!'; head -c 2000 /dev/zero; } >upx-low
has_line 'Packer:   UPX ("UPX!" at offset 0x66)' upx-low
has_line "$BY_HAND" upx-low
no_line "Packer:   no known signature" upx-low

{ printf 'MZ'; cat uniform uniform; printf 'UPX0.aspack'; } >upx-high
has_line 'Packer:   UPX ("UPX0" at offset 0x2002)' upx-high
has_line 'Packer:   ASPack (".aspack" at offset 0x2006)' upx-high
has_line "$PACKED" upx-high

# The search must recover after a false start, and survive a read boundary
printf 'UUPX!' >false-start
has_line 'Packer:   UPX ("UPX!" at offset 0x1)' false-start
{ head -c 65534 /dev/zero; printf 'UPX!'; } >across-reads
has_line 'Packer:   UPX ("UPX!" at offset 0xfffe)' across-reads

# Only the first occurrence of each signature
printf 'UPX!--UPX!' >twice
has_line 'Packer:   UPX ("UPX!" at offset 0x0)' twice
no_line 'Packer:   UPX ("UPX!" at offset 0x6)' twice

# A signature in a file that is not a program proves nothing
{ printf 'UPX!'; head -c 4096 /dev/zero; } >upx-in-data
has_line "$NORMAL" upx-in-data

printf 'UP' >incomplete
has_line "Packer:   no known signature" incomplete

# --- Inputs and errors ----------------------------------------------------------

expect 1 "" missing.bin
mkdir folder
expect 1 "" folder
expect 1 "" zeros uniform
expect 1 "" -z zeros
expect 1 "" -b 0 zeros
expect 1 "" -b 1023 zeros
expect 1 "" -b abc zeros
expect 1 "" -b -4096 zeros

actual=$("$hexray" entropy -q <fake-pe | head -1)
if [ "$actual" = "Type:     Windows executable (PE)" ]; then pass; else fail "redirected stdin: $actual"; fi
actual=$(cat fake-pe | "$hexray" entropy -q | head -1)
if [ "$actual" = "Type:     Windows executable (PE)" ]; then pass; else fail "stdin through a pipe: $actual"; fi

# --- Real and random data -------------------------------------------------------

head -c 1000000 /dev/urandom >random
has_line "Entropy:  8.00 of 8.00" -q random
has_line "High:     100% of the file (blocks above 7.20)" -q random

if [ "$(uname)" = "Darwin" ]; then
    has_line "Type:     macOS universal binary" -q /bin/ls
    has_line "$NORMAL" -q /bin/ls
fi

echo "$original: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
