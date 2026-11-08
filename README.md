# hexray

A static malware triage tool written in C. It looks at a suspicious file **without running it** and points out what deserves attention.

I am building it while learning C for cybersecurity: it started as a clone of `hexdump -C`, and each phase of the roadmap adds a new analysis and a new C skill.

> **Status:** phases 1 and 2 are done: hexray can show the bytes of a file and identify its real type. The remaining triage features are the roadmap below.

## Build

Needs `clang` and `make`. Developed on macOS (Apple Silicon).

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

## Roadmap

- [x] **Phase 1: hex dump.** A byte-for-byte clone of `hexdump -C`.
- [x] **Phase 2: file type detection.** Magic bytes and fake extensions.
- [ ] **Phase 3: strings.** Extraction and suspicious patterns.
- [ ] **Phase 4: entropy.** Spotting packed or encrypted files.
- [ ] **Phase 5: hashes.** SHA-256 written by hand.
- [ ] **Phase 6: executable headers.** ELF and PE.
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
