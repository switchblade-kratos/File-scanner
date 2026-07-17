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
      FILE *file = fopen(argv[2], "rb");
      if (file != NULL) {
        uint8_t file_chunk[4096]; // Read the file 4KB at a time
        size_t bytes_read;

        while ((bytes_read = fread(file_chunk, 1, 4096, file)) > 0) {
          sha256_update(&ctx, file_chunk, bytes_read);
        }

        sha256_hash(&ctx, hash);
        fclose(file);
        valid = true;
      } else
        printf("%s does not exist\n", argv[2]);
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
