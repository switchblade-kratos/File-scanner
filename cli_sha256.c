#include "sha256.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
  if (argc != 3) {
    printf("Please enter 2 arguments\n");
  } else {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    uint8_t hash[32];
    bool valid = false;

    if (!strcmp(argv[1], "-f")) {
      if (sha256(argv[2], hash) == 0) {
        valid = true;
      } else
        printf("%s file does not exist\n", argv[2]);
    } else if (!strcmp(argv[1], "-s")) {
      sha256_update(&ctx, (uint8_t *)argv[2], strlen(argv[2]));
      sha256_hash(&ctx, hash);
      valid = true;
    } else
      printf("Please enter a valid argument\n");
    if (valid) {
      for (int i = 0; i < 32; i++)
        printf("%02x", hash[i]);
      printf("\n");
    }
  }
  return 0;
}
