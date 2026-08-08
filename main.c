#include "loader.h"
#include "scanner.h"
#include <stdio.h>

int main(int argc, char *argv[]) {
  load_signatures("./test_signatures.txt");
  char dirname[] = "/home/username/";

  printf("Scanning %s\n", dirname);

  directory_scan(dirname);
  free_Signatures();
  return 0;
}
