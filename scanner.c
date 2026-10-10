#include "scanner.h"
#include "loader.h"
#include "sha256.h"
#include <dirent.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

void directory_scan(const char *dirname, ScanStats *stats) {
  if (dirname == NULL)
    return;

  if (strcmp(dirname, "/dev") == 0 || strcmp(dirname, "/proc") == 0 ||
      strcmp(dirname, "/sys") == 0 || strcmp(dirname, "/run") == 0) {
    return;
  }

  DIR *directory = opendir(dirname);
  if (directory == NULL) {
    fprintf(stderr, "ERROR: Could not open %s: %s\n", dirname, strerror(errno));
    stats->error++;
    return;
  }

  char path[2048];
  struct dirent *entry;
  while ((entry = readdir(directory)) != NULL) {
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
      continue;
    int n = snprintf(path, sizeof(path), "%s/%s", dirname, entry->d_name);
    if (n < 0 || (size_t)n >= sizeof(path)) {
      fprintf(stderr, "ERROR: Path too long: %s/%s\n", dirname, entry->d_name);
      stats->error++;
      continue;
    }
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
      directory_scan(path, stats);
    else if (type == DT_REG) {
      file_scan(path, stats);
    }
  }
  closedir(directory);
}

int file_scan(const char *filename, ScanStats *stats) {
  if (filename == NULL) {
    stats->error++;
    return -1;
  }

  struct stat st;

  if (stat(filename, &st) != 0) {
    fprintf(stderr, "ERROR: Could not access %s: %s\n", filename,
            strerror(errno));
    stats->error++;
    return -1;
  }

  if (!S_ISREG(st.st_mode)) {
    fprintf(stderr, "ERROR: %s is not a regular file\n", filename);
    stats->error++;
    return -1;
  }

  uint8_t hashval[32];

  int success = sha256(filename, hashval);
  if (success == 0) {
    stats->infected += binSearch_Signature(hashval, filename);
    stats->scanned++;
  } else {
    fprintf(stderr, "ERROR: Could not hash %s: %s\n", filename,
            strerror(errno));
    stats->error++;
    return -1;
  }
  return 0;
}
