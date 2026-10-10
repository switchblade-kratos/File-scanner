# File-scanner

A command-line malware scanner written in C. It computes the SHA-256 hash of files and checks them against a database of known malware signatures.

This is a learning project. It detects exact matches only, so it is not a replacement for a real antivirus.

## Features

- Scan a single file or a whole directory tree
- SHA-256 implementation written from scratch (no OpenSSL)
- Signatures are sorted once at startup and looked up with binary search, so each file check is O(log n)
- Malformed lines in the signature file are skipped with a warning that gives the line number
- Unreadable files, directories, device files and pipes passed as files are reported instead of hanging or crashing the scan
- Read errors are detected separately from end of file, so a partially read file is never reported as clean
- Summary of files scanned, matches and errors at the end of each run
- Exit codes that can be used in shell scripts

## Requirements

- Linux (or WSL). The scanner uses `dirent.h`, `stat`/`lstat` and `getopt_long`, which are not available with MSVC on Windows.
- GCC or Clang

## Building

```
gcc -Wall -Wextra -O2 main.c scanner.c loader.c sha256.c -o file-scanner
```

For development, a debug build with sanitizers catches memory errors:

```
gcc -Wall -Wextra -g -fsanitize=address,undefined main.c scanner.c loader.c sha256.c -o file-scanner
```

## Usage

```
Usage: ./file-scanner [options]

Options:
  -f, --file <path>        Scan a single file
  -d, --directory <path>   Scan a directory recursively
  -v, --verbose            Print each file as it is scanned
  -h, --help               Show this help and exit
```

Examples:

```
./file-scanner -f suspicious.bin
./file-scanner -d ~/Downloads
./file-scanner -d ~/Downloads -f ~/notes/report.pdf
```

Example output:

```
Loaded 12 signatures (0 lines skipped)
[!] Malware Found:
Filepath : /home/user/testdir/sub/deeper/evil2.txt
Match : EvilFile2

ERROR: Could not hash /home/user/testdir/locked.txt: Permission denied
Scanned: 3 | Infected: 1 | Errors: 1
```

### Exit status

| Code | Meaning |
|------|---------|
| 0 | No malware found |
| 1 | Malware found |
| 2 | Error (bad arguments, or signatures could not be loaded) |

This makes the scanner usable in scripts:

```
./file-scanner -d ./uploads || echo "Scan flagged something"
```

## Signature file

Signatures are read from `test_signatures.txt` in the current directory. Each line is a name and a SHA-256 hash separated by a colon:

```
# Lines starting with # or // are comments
EvilFile1: 3f1a...(64 hex characters)
EvilFile2: 9bc0...(64 hex characters)
```

- The hash must be exactly 64 hexadecimal characters (upper or lower case).
- Spaces around the name and hash are ignored.
- Windows line endings are handled.
- Invalid lines are skipped and reported with their line number.

To add a signature for a file, take its hash with `sha256sum`:

```
sha256sum somefile
```

## How it works

1. **Loading.** `loader.c` reads the signature file, validates each line, converts the hex string into 32 raw bytes and stores it in a growable array. The array is sorted with `qsort` once all lines are read.
2. **Walking.** `scanner.c` opens directories with `opendir`/`readdir` and recurses into subdirectories. If the filesystem does not report the entry type, it falls back to `lstat`. Symbolic links are not followed during directory scans, and `/dev`, `/proc`, `/sys` and `/run` are skipped.
3. **Checking.** Before hashing, each file is checked with `stat` so that only regular files are read. Directories, device files such as `/dev/zero` and named pipes are rejected with an error.
4. **Hashing.** `sha256.c` reads each file in 4 KB chunks, so large files do not have to fit in memory. A read error is reported as a failure instead of producing a hash of a partial file.
5. **Matching.** The 32-byte hash is looked up in the sorted array with `bsearch`, comparing raw bytes with `memcmp`.
6. **Reporting.** Counts are collected in a `ScanStats` struct that is passed through the recursion and printed at the end.

## Project structure

```
main.c               Argument parsing and program flow
scanner.c/h          Directory walking and per-file scanning
loader.c/h           Signature file parsing, validation and lookup
sha256.c/h           SHA-256 implementation
cli_sha256.c         Standalone tool that prints the SHA-256 of a file
test_signatures.txt  Sample signature database
```

## Testing

A quick manual test:

```
mkdir -p testdir/sub
echo "clean" > testdir/clean.txt
echo "fake malware" > testdir/sub/evil.txt
echo "locked" > testdir/locked.txt && chmod 000 testdir/locked.txt
sha256sum testdir/sub/evil.txt    # add this hash to test_signatures.txt
./file-scanner -d testdir
```

Expected: `evil.txt` is reported, `clean.txt` is not, and `locked.txt` produces a permission error without stopping the scan. If you run as root, the permission check does not apply.

Other useful checks:

```
./file-scanner -f /dev/zero    # rejected as not a regular file, does not hang
./file-scanner -f nope.txt     # reports that the file does not exist
./file-scanner; echo $?        # prints usage hint, exit code 2
```

## Limitations

- Only exact hash matches are detected. Changing a single byte of a file changes its hash.
- No heuristic, behavioural or archive scanning.
- The signature file path is currently fixed.
- Paths longer than 2047 characters are skipped.

## Planned

- `-s/--signatures <file>` to choose the signature database
- `-o/--output <file>` to write results to a log file
- Importing public hash lists (for example from abuse.ch MalwareBazaar)
- Makefile and automated tests in CI
- Parallel hashing with a thread pool

## License

MIT. See [LICENSE](LICENSE).
