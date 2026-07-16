#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint8_t data[64];
  uint32_t state[8];
  uint64_t bitlen;
  size_t datalen;
} SHA256_CTX;

void sha256_init(SHA256_CTX *ctx);
void sha256_transform(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len);

#endif
