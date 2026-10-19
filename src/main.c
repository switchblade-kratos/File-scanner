#include "loader.h"
#include "scanner.h"
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static void print_help(const char *prog) {
  printf("Usage: %s [options]\n\n", prog);
  printf("Scan files for known malware by comparing SHA-256 hashes\n");
  printf("against a signature database.\n\n");
  printf("Options:\n");
  printf("  -f, --file <path>        Scan a single file\n");
  printf("  -d, --directory <path>   Scan a directory recursively\n");
  printf("  -s, --signatures <file>  Signature file (default: "
         "./data/test_signatures.txt)\n");
  printf("  -v, --verbose            Print each file as it is scanned\n");
  printf("  -h, --help               Show this help and exit\n\n");
  printf("Exit status:\n");
  printf("  0  no malware found\n");
  printf("  1  malware found\n");
  printf("  2  error\n\n");
  printf("Examples:\n");
  printf("  %s -f download.bin\n", prog);
  printf("  %s -d ~/Downloads\n", prog);
}

int main(int argc, char *argv[]) {
  ScanStats stats = {0, 0, 0};

  bool help = false;

  int verbose = 0;
  static struct option long_opts[] = {
      {"help", no_argument, 0, 'h'},
      {"directory", required_argument, 0, 'd'},
      {"verbose", no_argument, 0, 'v'},
      {"file", required_argument, 0, 'f'},
      {"signatures", required_argument, 0, 's'},
      {0, 0, 0, 0} // array must end with this
  };
  int opt = 0;

  char *filename = NULL;
  char *dirname = NULL;
  char *signame = "./data/test_signatures.txt";

  while ((opt = getopt_long(argc, argv, "hd:f:s:v", long_opts, NULL)) != -1) {

    switch (opt) {
    case 'h':
      help = true;
      break;
    case 'd':
      dirname = optarg;
      break;
    case 'f':
      filename = optarg;
      break;
    case 's':
      signame = optarg;
      break;
    case 'v':
      verbose = 1;
      break;
    case '?':
      return 2;
    }
  }

  if (help) {
    print_help(argv[0]);
    return 0;
  }

  if (filename == NULL && dirname == NULL) {
    fprintf(stderr, "ERROR: Nothing to scan\n");
    fprintf(stderr, "Try %s -h for help\n", argv[0]);
    return 2;
  }

  int success = load_signatures(signame);
  if (success == -1) {
    fprintf(stderr, "Error: Could not load signatures\n");
    return 2;
  }
  if (dirname) {
    directory_scan(dirname, &stats);
  }
  if (filename) {
    file_scan(filename, &stats);
  }
  printf("Scanned: %d | Infected: %d | Errors: %d\n", stats.scanned,
         stats.infected, stats.error);
  free_Signatures();

  return stats.infected > 0 ? 1 : 0;
}
