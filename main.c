#include "loader.h"
#include "scanner.h"
#include <getopt.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
  load_signatures("./test_signatures.txt");
  char *filename = NULL;
  char *dirname = NULL;

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
      directory_scan(dirname);
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
