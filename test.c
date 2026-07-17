#include "sha256.h"
#include <stdio.h>
#include <string.h>

int main() {
  uint8_t hash[32];
  char str[] = "abc";
  SHA256_CTX ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, (uint8_t *)str, strlen(str));
  sha256_hash(&ctx, hash);
  for (int i = 0; i < 32; i++)
    printf("%02x", hash[i]);
  printf("\n");
  return 0;
}
