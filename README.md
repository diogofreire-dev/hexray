# hexray

A static malware triage tool written in C. It looks at a suspicious file **without running it** and points out what deserves attention.

I am building it while learning C for cybersecurity: it started as a clone of `hexdump -C`, and each phase of the roadmap adds a new analysis and a new C skill.

> **Status:** phases 1 to 6 are done: hexray can show the bytes of a file, identify its real type, extract suspicious strings, spot packed or encrypted content, compute its SHA-256 and read ELF and PE headers. The remaining triage features are the roadmap below.

## Build

Needs `clang` and `make` (and `python3` for `make test`). Developed on macOS (Apple Silicon).

```bash
make         # builds build/hexray
make test    # runs every test script
make help    # lists the other targets
```

`make debug` builds `build/debug/hexray` with AddressSanitizer and UndefinedBehaviorSanitizer, and `make test` runs the tests on both builds.

## Usage

### `hexray dump`: show the bytes

```
hexray dump [-v] [-s OFFSET] [-n LENGTH] [FILE]
```

| Option | Meaning |
|---|---|
| `-s OFFSET` | skip `OFFSET` bytes (decimal, or hex with `0x`) |
| `-n LENGTH` | show at most `LENGTH` bytes (decimal) |
| `-v` | show every line (no `*` for repeated lines) |
| `FILE` | file to read; without it, read standard input |

```console
$ build/hexray dump -n 32 src/main.c
00000000  2f 2f 20 68 65 78 72 61  79 3a 20 61 20 73 74 61  |// hexray: a sta|
00000010  74 69 63 20 6d 61 6c 77  61 72 65 20 74 72 69 61  |tic malware tria|
00000020
```

The output is identical to `hexdump -C`. `tests/test_dump.sh` checks this on empty files, zeros, random bytes, text, compiled binaries and stdin, across combinations of `-s`, `-n` and `-v`.

### `hexray type`: identify the real file type

```
hexray type [FILE...]
```

Identifies each file by its first bytes, whatever it is called. Without `FILE`, it reads standard input.

```console
$ build/hexray type invoice.pdf /bin/ls notes.txt
invoice.pdf: Windows executable (PE)  [MISMATCH: .pdf is the extension of: PDF document]
/bin/ls: macOS universal binary
notes.txt: Unknown (no known signature)
```

`MISMATCH` means the extension claims a format the content does not have. An extension hexray does not know is never flagged. The exit code is 0 when every file could be read, even if some were flagged, and 1 if any file could not be read.

### `hexray strings`: extract text and flag what stands out

```
hexray strings [-f] [-v] [-n MIN] [FILE]
```

| Option | Meaning |
|---|---|
| `-f` | show only the flagged strings |
| `-v` | show long strings in full (by default they are cut after 200 characters) |
| `-n MIN` | shortest string to report (default 4, smallest 2) |
| `FILE` | file to read; without it, read standard input |

Finds ASCII and UTF-16 (little-endian, the one Windows uses) strings, and prints the offset of each one so you can inspect it with `hexray dump -s`.

```console
$ build/hexray strings -f dropper.bin
00001a40  ascii   http://203.0.113.5/stage2  [URL, IP]
00001a80  utf-16  cmd.exe /c del %TEMP%\a.bat  [SHELL]
00001b00  utf-16  Software\Microsoft\Windows\CurrentVersion\Run  [PERSISTENCE]
```

| Flag | Raised by |
|---|---|
| `URL` | `http://`, `https://`, `ftp://` |
| `IP` | an IPv4 address |
| `SHELL` | `cmd.exe`, `powershell`, `/bin/sh`, `/bin/bash` |
| `ENCODED-COMMAND` | `powershell` together with `-enc` |
| `PERSISTENCE` | the registry `CurrentVersion\Run` keys |
| `BASE64` | 40 or more Base64 characters, mixing upper case, lower case and digits |

A flag means "look at this", not "this is malware". Legitimate programs contain URLs and shell paths too, and a four-part version number looks exactly like an IP address.

### `hexray entropy`: spot packed or encrypted content

```
hexray entropy [-q] [-b SIZE] [FILE]
```

| Option | Meaning |
|---|---|
| `-q` | show only the summary, without the graph |
| `-b SIZE` | size of each block in bytes (decimal, or hex with `0x`; default 4096, smallest 1024) |
| `FILE` | file to read; without it, read standard input |

Shows the Shannon entropy of each block, from 0 (all bytes the same) to 8 (pure noise), and searches the file for the signatures that common packers leave behind.

```console
$ build/hexray entropy sample.exe
Offset    Entropy  0 to 8
00000000  3.41     ##############..................
00001000  7.98     ################################  HIGH
00002000  7.97     ################################  HIGH
00003000  7.98     ################################  HIGH

Type:     Windows executable (PE)
Size:     16384 bytes
Entropy:  7.44 of 8.00
High:     75% of the file (blocks above 7.20)
Packer:   UPX ("UPX!" at offset 0x3e0)
Verdict:  PACKED? Most of this executable is high entropy
```

The verdict takes the file type into account: an executable that is at least 70% high entropy is probably packed, while a ZIP or JPEG is compressed by design. Like the string flags, it is a reason to look closer and not a proof. Malware can also keep its entropy low on purpose.

### `hexray hash`: fingerprint a file

```
hexray hash [FILE...]
```

Prints the SHA-256 of each file, in the same format as `shasum -a 256`. Without `FILE`, it reads standard input. SHA-256 is implemented by hand in `src/sha256.c`, with no crypto library, and `tests/test_hash.sh` checks it against the NIST test vectors and the real `shasum`.

```console
$ printf 'abc' | build/hexray hash
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  -
```

Search the hash on VirusTotal or MalwareBazaar to see whether a file is already known as malware. Search the hash and do not upload the file: uploads can be seen by others, including whoever made the malware, and a private document would be exposed.

### `hexray headers`: sections and imports of ELF and PE files

```
hexray headers [-f] [FILE]
```

| Option | Meaning |
|---|---|
| `-f` | show only the flagged imports |
| `FILE` | file to read; without it, read standard input |

```console
$ build/hexray headers -f sample.exe
Format:   PE32+, x86-64
Entry:    0x1234

Name              Offset    Size      Entropy  Perms
.text             00000400  00001a00  6.21     r-x
.data             00001e00  00000400  2.87     rw-
.packed           00002200  00006000  7.97     rwx  HIGH

Imports:  41
  KERNEL32.dll!WriteProcessMemory  [INJECTION]
  KERNEL32.dll!CreateRemoteThread  [INJECTION]
  KERNEL32.dll!IsDebuggerPresent  [ANTI-ANALYSIS]
Warning:  section .packed is both writable and executable
Warning:  imports match the classic code injection pattern
```

Import flags: `INJECTION`, `ANTI-ANALYSIS`, `DOWNLOAD`, `EXECUTION`, `KEYLOGGING` and `PERSISTENCE`. As with the other commands, they say where to look and do not prove anything: many legitimate programs call `IsDebuggerPresent`.

Executables are hostile input, so every offset and size in them is treated as untrusted. All reads go through bounds-checked functions in `src/binary.c`. A damaged file gives whatever could still be read plus a warning, and `tests/test_headers.sh` runs corrupted and truncated files through the sanitized build.

Limitations: Mach-O is not supported, and an ELF with its section table stripped shows no sections or imports, even though the imports could still be recovered through its program headers.

## Roadmap

- [x] **Phase 1: hex dump.** A byte-for-byte clone of `hexdump -C`.
- [x] **Phase 2: file type detection.** Magic bytes and fake extensions.
- [x] **Phase 3: strings.** Extraction and suspicious patterns.
- [x] **Phase 4: entropy.** Spotting packed or encrypted files.
- [x] **Phase 5: hashes.** SHA-256 written by hand.
- [x] **Phase 6: executable headers.** ELF and PE.
- [ ] **Phase 7: signatures.** A mini YARA.

Each phase will be added as a new subcommand.

### Phase 2: what kind of file is it? (magic bytes)

Most formats start with a fixed signature:

| Bytes | Format |
|---|---|
| `4d 5a` (`MZ`) | Windows executable (PE: `.exe`, `.dll`) |
| `7f 45 4c 46` (`.ELF`) | Linux executable |
| `cf fa ed fe` | macOS executable (Mach-O 64-bit) |
| `ca fe ba be` | macOS universal binary / Java class |
| `50 4b 03 04` (`PK`) | ZIP, also `.docx`, `.xlsx`, `.jar`, `.apk` |
| `d0 cf 11 e0` | old Office documents (`.doc`, `.xls`, classic macro malware) |
| `25 50 44 46` (`%PDF`) | PDF |
| `89 50 4e 47` | PNG |
| `ff d8 ff` | JPEG |

Flag a **mismatch**: an `invoice.pdf` that starts with `MZ` is a Windows program in disguise.

### Phase 3: strings

- Extract every run of 4 or more printable characters, and also UTF-16 strings (Windows stores text as `H.e.l.l.o.`).
- Highlight suspicious ones: URLs and IPs (command-and-control servers), `cmd.exe`, `powershell -enc`, registry `Run` keys (persistence), long Base64 blobs.

### Phase 4: entropy (is it packed or encrypted?)

- **Shannon entropy** measures how random the bytes are: 0 means all the same, 8 means completely random.
- Normal code and text score about 4 to 6. Compressed or encrypted data scores close to 8.
- Show the entropy of each block of the file as a small bar graph. A program that is almost all high entropy is probably **packed** (its real code is hidden and only unpacked when it runs), a common malware trick. Also look for packer signatures such as `UPX!`.

### Phase 5: hashes

- Implement **SHA-256** by hand (practice with bitwise operators and `uint32_t`).
- A hash identifies a file, so it can be searched on VirusTotal or MalwareBazaar to see whether the file is already known as malware, without uploading it.

### Phase 6: executable headers (ELF / PE)

- Parse the headers with `struct`s to list the **sections**, their entropy and the **imported functions**.
- Flag suspicious Windows imports: `VirtualAlloc` + `WriteProcessMemory` + `CreateRemoteThread` (code injection), `IsDebuggerPresent` (anti-analysis), `URLDownloadToFile`.

### Phase 7: signatures (a mini YARA)

- Read rules from a file (`name: hex pattern`, with `??` as a wildcard byte) and report which rules match.
- This is the idea behind antivirus signatures and **YARA**, the standard tool of malware analysts.

## Safety rules

- **Static analysis only: never run a sample.** hexray only reads bytes, and no feature may ever execute the file being analysed.
- Start with **harmless files**: your own programs, system binaries and the **EICAR test file** (a standard string that every antivirus detects but that does nothing).
- Real samples (for example from MalwareBazaar) come in password-protected ZIPs. Only open them inside an **isolated virtual machine** with no shared folders, never on your own computer.
- **Never commit samples.** The `samples/` folder is in `.gitignore` for that reason.

## License

[MIT](LICENSE)
