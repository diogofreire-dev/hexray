# How hexray works

*[Versão em português](how-it-works.pt.md)*

A step-by-step explanation of what hexray does and how the code does it, written for someone who knows basic C. For the options of each command, see the [README](../README.md).

## The big picture

Imagine an email with an attachment called `invoice.pdf`. You could open it to see what it does, but if it is malware, your computer is already infected.

hexray answers **"what is this file?" without ever running it**. It only reads bytes, the way you would read text. This is called static analysis.

A file is just a sequence of numbers from 0 to 255. Each hexray command looks at those numbers in a different way:

| Command | The question it answers |
|---|---|
| `dump` | What bytes are in here? |
| `type` | What kind of file is this really? |
| `strings` | Is there readable text inside? |
| `entropy` | Is it hiding something? |
| `hash` | Has anyone seen this file before? |
| `headers` | What does this program ask the system to do? |
| `scan` | Does it look like something I already know? |

## How the code is organised

| Where | What it does |
|---|---|
| `src/main.c` | Reads the first word you typed and calls the right command, through a table of function pointers |
| `src/dump.c`, `type.c`, `strscan.c`, `entropy.c`, `hash.c`, `headers.c`, `scan.c` | One file per command |
| `src/sha256.c` | The SHA-256 algorithm, separate from the command that uses it |
| `src/binary.c`, `pe.c`, `elf.c` | Safe reading of untrusted files, and the two executable formats |
| `src/util.c` | Small helpers that several commands share |
| `tests/` | One script per command, run by `make test` |
| `rules/starter.rules` | A small set of signatures for `scan` |

The `Makefile` builds two versions. `build/hexray` is the normal one. `build/debug/hexray` includes AddressSanitizer and UndefinedBehaviorSanitizer, which stop the program when it makes a memory mistake. The tests run on both.

To follow the experiments below, build first:

```bash
make
```

## 1. `dump`: show the bytes

**The idea.** Read 16 bytes at a time and print each line with the offset, the bytes in hexadecimal and the same bytes as text. Bytes that cannot be printed appear as `.`. Repeated lines are replaced by a single `*`.

**Read in `dump.c`.** Start with `dump()`, the main loop, then `print_line()`. After that, `parse_options()` shows how `getopt` works.

**C you will meet.** `fread`, `structs`, `static` functions, `printf` formats such as `%02x`, and `memcmp`.

**Try it.**

```bash
build/hexray dump -n 64 README.md
```

**Check yourself.**
- Why does the code keep `previous_count` and not only the `previous` array?
- Why does `-n 0` have to be stored separately from "no `-n` was given"?
- Why does `skip_bytes()` read and discard data rather than use `fseek`?

## 2. `type`: what is this file really?

**The idea.** Most formats start with fixed bytes called *magic bytes*: a PDF starts with `%PDF`, and a Windows program with `MZ`. The operating system does not care what a file is called, and attackers use that. If `invoice.pdf` is really a Windows program, hexray prints `MISMATCH`.

Two bytes are not much proof, because some text could start with `MZ` by chance. So `is_pe()` also follows the pointer stored at offset `0x3c` and checks that a real PE header is there.

**Read in `type.c`.** The `types[]` table first, then `identify()`, `is_pe()`, `find_extension()` and `find_mismatch()`.

**C you will meet.** Arrays of structs, function pointers (the `confirm` field), bit shifts and big-endian numbers in `read_be32()`.

**Try it.**

```bash
build/hexray type /bin/ls README.md
```

**Check yourself.**
- Universal binaries and Java classes start with the same 4 bytes. How does the code tell them apart?
- Why is `.bak` never flagged, while `.pdf` can be?
- Why does `(uint32_t) bytes[0] << 24` need the cast?

## 3. `strings`: find readable text

**The idea.** Walk through the file and collect every run of printable characters. A URL, `cmd.exe` or a registry key can give away what a program intends to do.

Windows usually stores text as UTF-16, where each letter takes two bytes: `H`, `0`, `e`, `0`. Looking only for ASCII would miss it. A UTF-16 string can start on an even or odd offset, so the scanner follows both alignments at once. Each byte is the second half of a unit that began on the byte before.

**Read in `strscan.c`.** `process_byte()` is the core. Then `feed()`, `run_append()` and `run_finish()`. Finally `collect_flags()` with `has_ipv4()` and `has_base64_blob()`.

**C you will meet.** `realloc` to grow a buffer, a pointer to a pointer in `read_octet()`, and `%.*s`.

**Try it.**

```bash
build/hexray strings -f /usr/bin/curl
```

**Check yourself.**
- Why does `run_append()` store the result of `realloc` in a new variable first?
- What exactly decides that a run of characters is Base64, and which false positives does each rule remove?
- Why are the flags computed on the whole string, even when the display cuts it?

## 4. `entropy`: is it hiding something?

**The idea.** Shannon entropy measures how unpredictable the bytes are, from 0 to 8 bits per byte. All bytes equal gives 0. All 256 values equally common gives 8. Code and text land around 4 to 6, and compressed or encrypted data lands close to 8.

Malware uses *packing*: the real code is stored encrypted and only unpacked when the program runs, so static tools find nothing to read. A program that is mostly high entropy is suspicious. A JPEG is not, because it is compressed by design, so the verdict also looks at the file type.

The formula is `H = -sum(p * log2(p))`, where `p` is the fraction of the bytes with a given value. With two values at half each: `-(0.5 * -1 + 0.5 * -1) = 1`.

**Read in `entropy.c`.** `shannon_entropy()`, `finish_block()`, `update_packers()` and `verdict()`.

**C you will meet.** `double`, converting before dividing, `log2`, linking with `-lm`, and `memset`.

**Try it.**

```bash
build/hexray entropy -b 0x8000 /bin/ls
```

**Check yourself.**
- What would `counts[value] / total` give without the `double` conversion?
- Why can a very small block never score high, even if it is pure noise?
- Why does a signature split across two reads still get found?

## 5. `hash`: has anyone seen this file?

**The idea.** SHA-256 turns any amount of data into a 256-bit fingerprint. Change one bit of the input and about half of the output changes. You can search that value on VirusTotal or MalwareBazaar to see whether a file is known, without uploading it.

The algorithm starts with 8 fixed 32-bit numbers. Each 64-byte block of data stirs them through 64 rounds of rotations, XORs and additions. The 8 numbers at the end are the hash.

**Read in `sha256.c`.** `sha256_update()` to see how data is split into blocks, `sha256_final()` for the padding, then `compress()`.

**C you will meet.** `uint32_t`, unsigned overflow, bit rotation, `const void *`.

**Try it.** Both lines must print the same hash:

```bash
build/hexray hash README.md
```

```bash
shasum -a 256 README.md
```

**Check yourself.**
- Why must these additions use unsigned types?
- What does the padding add at the end of the message, and when does it need one extra block?
- Why is the interface split into `init`, `update` and `final`?

## 6. `headers`: what does this program ask for?

**The idea.** An executable is like a book with a table of contents. *Sections* are the chapters: code, data and so on. *Imports* are the functions it asks the operating system for. Asking for `WriteProcessMemory` and `CreateRemoteThread` suggests injecting code into another process.

**The most important idea in the project: everything in the file can be a lie.** If a header says "the table is at byte 4,000,000,000" and the program believes it, it reads memory it should not, and can crash or be exploited. So every read in the parsers goes through `src/binary.c`, which checks first that those bytes really exist.

**How a PE file is laid out.**
1. The file starts with `MZ`, and the 4 bytes at `0x3c` say where the real PE header is.
2. After that come the COFF header, the optional header and the section table.
3. The optional header says where the import table is, as an RVA: an address in memory, not in the file. `rva_to_offset()` translates it using the section table.
4. Each import entry names a DLL and leads to its list of functions.

**ELF is simpler.** A header points to the section table, and imported functions are the symbols marked as undefined in `.dynsym`.

**Read, in this order.** `binary.c` (start with `reader_has()`, then `reader_string()`), `pe.c` (`pe_parse()`, `rva_to_offset()`, `read_imports()`, `read_thunks()`), `elf.c` (`elf_parse()`), and `headers.c` (`analyse()`, `flag_for_import()`).

**C you will meet.** Integer overflow in bounds checks, little and big endian, and pointers kept inside a buffer.

**Try it.** macOS has no ELF or PE files in its system folders, so use the harmless test files:

```bash
rm -rf build/fixtures && mkdir -p build/fixtures && python3 tests/make_headers_fixtures.py build/fixtures
```

```bash
build/hexray headers build/fixtures/valid-pe64.exe
```

```bash
build/hexray headers build/fixtures/pe-cut-in-imports
```

**Check yourself.**
- Why does `reader_has()` use `r->size - offset < length` and not `offset + length > r->size`?
- Why does `reader_string()` need `memchr`? What would happen without it?
- Why not simply cast the file to a `struct`?
- What stops a file from claiming millions of sections?

## 7. `scan`: search for known patterns

**The idea.** It is a Ctrl+F for bytes. A rules file lists patterns in hexadecimal, where `??` means any byte, and hexray reports which ones it finds. Wildcards matter because malware variants change small details around the same code. Antivirus signatures and YARA are built on this idea.

**The trick for speed.** Trying every position would be slow on a file full of the byte a pattern starts with. So `find_rule()` looks for the byte of the pattern that is *rarest in this file*, using `memchr`, and compares the whole pattern only where that byte appears.

**Read in `scan.c`.** `parse_line()`, `parse_pattern()`, `find_rule()`, `matches_at()`.

**C you will meet.** `getline`, cutting a string in place with `'\0'`, `int16_t` to hold 257 different values, and `memchr`.

**Try it.**

```bash
build/hexray scan -r rules/starter.rules README.md
```

**Check yourself.**
- Why can a pattern not be stored in a plain `unsigned char` array?
- Why does `positions` equal `size - rule->length + 1`?
- Why does `README.md` match rules for UPX? What does that say about signatures?

## How it was tested

| Technique | What it proves | Where |
|---|---|---|
| Comparing with a real tool | The output of `dump` and `hash` is identical to `hexdump -C` and `shasum` | `tests/test_dump.sh`, `tests/test_hash.sh` |
| Official test vectors | SHA-256 follows the standard | `tests/test_hash.sh` |
| Known answers | A file built byte by byte has a result that can be worked out by hand | `tests/test_entropy.sh`, `tests/test_type.sh`, `tests/test_strings.sh`, `tests/test_scan.sh` |
| Broken files, on the sanitized build | A corrupted file gives warnings and not a memory error | `tests/test_headers.sh` |

## Where to go next

Read the code in this order, from the simplest to the hardest: `dump.c`, `type.c`, `strscan.c`, `entropy.c`, `scan.c`, `sha256.c`, `binary.c`, `pe.c`.

Then change something yourself. Two good first projects are flagging double extensions such as `invoice.pdf.exe`, and recognising the short form `powershell -e`. Add a test for each, and run `make test`.

hexray only suggests where to look. A flag or a match does not prove that a file is malicious, and a clean result does not prove that it is safe.
