#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint8_t buffer[64];
  uint32_t state[8];
  uint64_t bitlen;
  size_t len;
} SHA256_CTX;

void sha256_init(SHA256_CTX *ctx);

#endif
