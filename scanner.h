#ifndef SCANNER_H
#define SCANNER_H

typedef struct {
  int scanned;
  int infected;
  int error;
} ScanStats;

void directory_scan(const char *dirname, ScanStats *stats);
int file_scan(const char *filename, ScanStats *stats);
#endif // SCANNER_H
