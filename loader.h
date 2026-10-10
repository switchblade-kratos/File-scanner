#ifndef LOADER_H
#define LOADER_H

#include <stdint.h>

int binSearch_Signature(uint8_t hash[32], const char *filepath);
int load_signatures(const char *filename);
void free_Signatures(void);

#endif // !LOADER_H
