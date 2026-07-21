#include "sha256.h"
#include <dirent.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

typedef struct {
  uint8_t bytes[32];
} HASH256;

void directory_scan(const char *dirname) {
  if (strcmp(dirname, "/dev") == 0 || strcmp(dirname, "/proc") == 0 ||
      strcmp(dirname, "/sys") == 0 || strcmp(dirname, "/run") == 0) {
    return;
  }
  DIR *directory = opendir(dirname);
  if (directory == NULL) {
    return;
  }

  char path[2048];
  struct dirent *entry;
  while ((entry = readdir(directory)) != NULL) {
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
      continue;
    unsigned char type = entry->d_type;
    if (type == DT_UNKNOWN) {
      struct stat statbuf;
      if (lstat(path, &statbuf) == 0) {
        if (S_ISDIR(statbuf.st_mode)) {
          type = DT_DIR;
        } else if (S_ISREG(statbuf.st_mode)) {
          type = DT_REG;
        }
      }
    }
    snprintf(path, sizeof(path), "%s/%s", dirname, entry->d_name);
    if (type == DT_DIR)
      directory_scan(path);
    else if (type == DT_REG) {
      HASH256 hashval;
      sha256(path, hashval.bytes);
      printf("File: %s -> ", path);
      for (int i = 0; i < 32; i++)
        printf("%02x", hashval.bytes[i]);
      printf("\n");
    }
  }
  closedir(directory);
}
int main(int argc, char *argv[]) {
  char dirname[] = "/home/username/test";

  directory_scan(dirname);

  return 0;
}
