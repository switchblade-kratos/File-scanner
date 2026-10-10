#include "loader.h"
#include "scanner.h"
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
  int success = load_signatures("./test_signatures.txt");
  if (success == -1) {
    fprintf(stderr, "Error: Could not load signatures: %s", strerror(errno));
    return -1;
  }
  char *filename = NULL;
  char *dirname = NULL;

  ScanStats stats = {0, 0, 0};

  int verbose = 0;
  static struct option long_opts[] = {
      {"help", no_argument, 0, 'h'},
      {"directory", required_argument, 0, 'd'},
      {"verbose", no_argument, 0, 'v'},
      {0, 0, 0, 0} // array must end with this
  };
  int opt = 0;
  while ((opt = getopt_long(argc, argv, "hd:v", long_opts, NULL)) != -1) {
    switch (opt) {
    case 'h': // print_help(argv[0]);
      return 0;
    case 'd':
      dirname = optarg;
      directory_scan(dirname, &stats);
      printf("%d Files scanned, %d infected, %d errors\n", stats.scanned,
             stats.infected, stats.error);
      break;
    case 'v':
      verbose = 1;
      break;
    case '?':
      return 1;
    }
  }
  free_Signatures();
  return 0;
}
