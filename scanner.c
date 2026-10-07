#include "loader.h"
#include "sha256.h"
#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

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

    snprintf(path, sizeof(path), "%s/%s", dirname, entry->d_name);

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
    if (type == DT_DIR)
      directory_scan(path);
    else if (type == DT_REG) {
      uint8_t hashval[32];
      int success = 0;
      success = sha256(path, hashval);
      if (success == 0)
        binSearch_Signature(hashval, path);
      else
        fprintf(stderr, "ERROR: Could not hash %s : %s\n", path,
                strerror(errno));
    }
  }
  closedir(directory);
}
