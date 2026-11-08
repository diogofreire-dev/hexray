#!/usr/bin/env bash
# Checks the output and exit code of `hexray scan`.
#
# Usage: tests/test_scan.sh path/to/hexray
#
# Written for bash 3.2, the version that ships with macOS. The fixtures are harmless:
# the antivirus test string appears only in part, so no antivirus reacts to this.

set -u

if [ $# -ne 1 ] || [ ! -x "$1" ]; then
    echo "Usage: $0 path/to/hexray" >&2
    exit 2
fi

# Absolute paths, because the tests run from inside a temporary folder
hexray=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
starter=$(cd "$(dirname "$0")/.." && pwd)/rules/starter.rules
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

# expect STATUS OUTPUT ARGUMENTS...  compares against `hexray scan ARGUMENTS`
expect() {
    local status=$1 output=$2 actual actual_status
    shift 2
    actual=$("$hexray" scan "$@" 2>errors)
    actual_status=$?
    if [ "$actual_status" -eq "$status" ] && [ "$actual" = "$output" ] &&
        { [ "$status" -eq 0 ] || [ -s errors ]; } && ! grep -Eq 'Sanitizer|runtime error' errors; then
        pass
    else
        fail "scan $*"
        echo "  expected ($status): $output"
        echo "  actual ($actual_status): $actual"
        head -6 errors | sed 's/^/  /'
    fi
}

# matches RULE_TEXT FILE_FORMAT EXPECTED: one rule, one file, built with printf.
# EXPECTED is an offset like 0x3, or "none".
matches() {
    printf '%s\n' "$1" >r.rules
    printf "$2" >f.bin
    if [ "$3" = "none" ]; then
        expect 0 "f.bin: no rules matched" -r r.rules f.bin
    else
        expect 0 "f.bin: only at $3" -r r.rules f.bin
    fi
}

# rejected RULE_TEXT LINE REASON: the rules file must fail with that message
rejected() {
    printf '%b' "$1" >bad.rules
    "$hexray" scan -r bad.rules f.bin >output 2>errors
    local status=$?
    if [ "$status" -eq 1 ] && [ ! -s output ] && grep -Fq -- "bad.rules:$2: $3" errors &&
        ! grep -Eq 'Sanitizer|runtime error' errors; then
        pass
    else
        fail "rules [$1]: expected line $2 \"$3\" (exit code $status)"
        head -6 errors | sed 's/^/  /'
    fi
}

# --- Where a pattern matches ----------------------------------------------------

matches 'only: 41 42' 'AB'               0x0
matches 'only: 41 42' 'xxAB'             0x2
matches 'only: 41 42' 'ABxx'             0x0
matches 'only: 41 42' 'A'                none
matches 'only: 41 42' 'BA'               none
matches 'only: 41 42' ''                 none
matches 'only: 41 42' 'xABxABx'          0x1
matches 'only: 00 ff' '\x00\xff'         0x0
matches 'only: ff' '\x00\x01\xff'        0x2

# Repeated bytes, where a naive restart would skip the real match
matches 'only: 41 41 42' 'AAAB'          0x1
matches 'only: 41 42 41 43' 'ABABAC'     0x2

# Wildcards: in the middle, and at the edges of the file
matches 'only: 41 ?? 43' 'ABC'           0x0
matches 'only: 41 ?? 43' 'xAzCx'         0x1
matches 'only: 41 ?? 43' 'AC'            none
matches 'only: 41 ?? ?? 44' 'AxyD'       0x0
matches 'only: ?? 41' 'xA'               0x0
matches 'only: ?? 41' 'A'                none
matches 'only: ?? 41' 'Ax'               none
matches 'only: 41 ??' 'Ax'               0x0
matches 'only: 41 ??' 'A'                none
matches 'only: 41 ??' 'xA'               none
matches 'only: ?? 41 ??' 'xAx'           0x0
matches 'only: ?? 41 ??' 'Ax'            none
matches 'only: ?? 41 ??' 'xA'            none

# Wildcards match any value, including zero and 0xff
matches 'only: 41 ?? 43' 'A\x00C'        0x0
matches 'only: 41 ?? 43' 'A\xffC'        0x0

# The first candidate fails and a later one works, on the rarest byte
matches 'only: 00 00 01' '\x00\x00\x00\x00\x01'  0x2
matches 'only: 41 42 ?? 42' 'ABxAByB'    0x3

# How a pattern can be written
matches 'only: 4142' 'xAB'               0x1
matches 'only: 41  42' 'xAB'             0x1
matches 'only: 4A 4b' 'xJK'              0x1
matches 'only:41 42' 'xAB'               0x1
matches '  only  :  41 42  ' 'xAB'       0x1
matches 'only: 41 42 # a comment' 'xAB'  0x1

# A rule name with those characters prints as itself
printf 'with-dash.and_more: 41\n' >r.rules
printf 'A' >f.bin
expect 0 "f.bin: with-dash.and_more at 0x0" -r r.rules f.bin

# --- A pattern far into a file --------------------------------------------------

{ head -c 3000000 /dev/zero; printf 'needle'; } >deep
printf 'found: 6e 65 65 64 6c 65\nmissing: 6e 65 65 64 6c 66\n' >r.rules
expect 0 "deep: found at 0x2dc6c0" -r r.rules deep

# Plenty of false starts, all of the byte the pattern begins with. It must still be quick.
head -c 2000000 /dev/zero >zeros
printf 'late: 00 00 00 00 00 00 00 00 42\n' >r.rules
expect 0 "zeros: no rules matched" -r r.rules zeros
{ cat zeros; printf 'B'; } >zeros-b
expect 0 "zeros-b: late at 0x1e8478" -r r.rules zeros-b

# --- Several rules and files ----------------------------------------------------

cat >many.rules <<'EOF'
# A comment on its own line

first: 41 42

second: 43 44   # after a pattern
never: 7a 7a 7a
EOF
printf 'CDxxAB' >ab
printf 'nothing' >none
expect 0 "ab: first at 0x4
ab: second at 0x0" -r many.rules ab
expect 0 "ab: first at 0x4
ab: second at 0x0
none: no rules matched" -r many.rules ab none
expect 1 "ab: first at 0x4
ab: second at 0x0
none: no rules matched" -r many.rules ab missing.bin none

# Windows line endings in the rules file
printf 'first: 41 42\r\nsecond: 43 44\r\n' >crlf.rules
expect 0 "ab: first at 0x4
ab: second at 0x0" -r crlf.rules ab

# No final newline
printf 'first: 41 42' >no-newline.rules
expect 0 "ab: first at 0x4" -r no-newline.rules ab

# A very long line is fine as long as the pattern is inside the limit
{ printf 'long: 41 '; head -c 20000 /dev/zero | tr '\000' ' '; printf '42\n'; } >spaces.rules
printf 'AB' >spaced
expect 0 "spaced: long at 0x0" -r spaces.rules spaced

# Standard input
actual=$("$hexray" scan -r many.rules <ab)
if [ "$actual" = "(stdin): first at 0x4
(stdin): second at 0x0" ]; then pass; else fail "redirected stdin: $actual"; fi
actual=$(cat ab | "$hexray" scan -r many.rules)
if [ "$actual" = "(stdin): first at 0x4
(stdin): second at 0x0" ]; then pass; else fail "stdin through a pipe: $actual"; fi

# Terminal escape sequences in a file name must not reach the screen
escape_name=$(printf 'evil\033[31m.bin')
printf 'AB' >"$escape_name"
expect 0 "evil?[31m.bin: first at 0x0" -r many.rules "$escape_name"

printf 'AB' >./-dash
expect 0 "-dash: first at 0x0" -r many.rules -- -dash

# --- Invalid rules --------------------------------------------------------------

printf 'x' >f.bin
rejected 'nocolon 41\n' 1 "expected  name: hex pattern"
rejected '# fine\n\nnocolon 41\n' 3 "expected  name: hex pattern"
rejected ': 41\n' 1 "the rule name must have"
rejected 'bad name: 41\n' 1 "the rule name can only use"
rejected 'bad/name: 41\n' 1 "the rule name can only use"
rejected 'empty:\n' 1 "the pattern is empty"
rejected 'odd: 4\n' 1 "each byte must be two hex digits"
rejected 'odd: 41 4\n' 1 "each byte must be two hex digits"
rejected 'split: 4 1\n' 1 "each byte must be two hex digits"
rejected 'hex: 4g\n' 1 "each byte must be two hex digits"
rejected 'half: 4?\n' 1 "each byte must be two hex digits"
rejected 'half: ?4\n' 1 "each byte must be two hex digits"
rejected 'single: ?\n' 1 "each byte must be two hex digits"
rejected 'wild: ??\n' 1 "a pattern with only ?? would match everything"
rejected 'wild: ?? ?? ??\n' 1 "a pattern with only ?? would match everything"
rejected 'twice: 41\ntwice: 42\n' 2 "another rule already has this name"
rejected 'ok: 41\nbad\n' 2 "expected  name: hex pattern"

long_name=$(head -c 64 /dev/zero | tr '\000' 'n')
rejected "$long_name: 41\n" 1 "the rule name must have"
fit_name=$(head -c 63 /dev/zero | tr '\000' 'n')
printf '%s: 78\n' "$fit_name" >r.rules
expect 0 "f.bin: $fit_name at 0x0" -r r.rules f.bin

too_long=$(head -c 4097 /dev/zero | tr '\000' '.' | sed 's/\./41/g')
rejected "big: $too_long\n" 1 "the pattern is too long"
longest=$(head -c 4096 /dev/zero | tr '\000' '.' | sed 's/\./41/g')
printf 'big: %s\n' "$longest" >r.rules
head -c 4096 /dev/zero | tr '\000' 'A' >as
expect 0 "as: big at 0x0" -r r.rules as

: >empty.rules
expect 1 "" -r empty.rules f.bin
printf '# only comments\n\n' >comments.rules
expect 1 "" -r comments.rules f.bin
expect 1 "" -r missing.rules f.bin
expect 1 "" f.bin
expect 1 "" -z -r many.rules f.bin

# --- The starter rules ----------------------------------------------------------

printf 'x UPX! y' >upx
expect 0 "upx: upx_magic at 0x2" -r "$starter" upx

printf 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE' >eicar-part
expect 0 "eicar-part: eicar_test_file at 0x0" -r "$starter" eicar-part

printf 'x\000Software\\Microsoft\\Windows\\CurrentVersion\\Run' >run-key
expect 0 "run-key: run_key_ascii at 0x1d" -r "$starter" run-key

printf 'C\000u\000r\000r\000e\000n\000t\000V\000e\000r\000s\000i\000o\000n\000\\\000R\000u\000n\000' >run-utf16
expect 0 "run-utf16: run_key_utf16 at 0x0" -r "$starter" run-utf16

printf 'powershell -EncodedCommand x' >encoded
expect 0 "encoded: powershell_encoded_ascii at 0xb" -r "$starter" encoded

# The header fields between the magic and the machine can be anything
printf '\x7fELF\x02\x01\x01\xaa\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44\x55\x3e\x00' >elf
expect 0 "elf: elf64_x86_64 at 0x0" -r "$starter" elf
printf '\x7fELF\x02\x01\x01\xaa\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44\x55\xb7\x00' >elf-arm
expect 0 "elf-arm: no rules matched" -r "$starter" elf-arm

printf 'just an ordinary file' >clean
expect 0 "clean: no rules matched" -r "$starter" clean

echo "$original: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
