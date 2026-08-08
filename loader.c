#include "loader.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  uint8_t hash[32];
  char name[64];
} Signatures;

int compare_signatures(const void *a, const void *b) {
  // Cast the void pointers back to our custom struct
  const Signatures *sigA = (const Signatures *)a;
  const Signatures *sigB = (const Signatures *)b;

  // Compare only the 32-byte binary hashes using memcmp
  return memcmp(sigA->hash, sigB->hash, 32);
}

// Converts a single ASCII hex character into its 4-bit integer value
static uint8_t hex_char_to_val(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0'; // '0' is 48. If c is '5' (53), 53 - 48 = 5.
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10; // 'a' becomes 10, 'b' becomes 11, etc.
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10; // Handles uppercase just in case
  }
  return 0; // Failsafe for invalid characters
}

// Converts a 64-character hex string into a raw 32-byte array
void hex_string_to_binary(const char *hex_string, uint8_t *out_binary) {
  for (int i = 0; i < 32; i++) {
    // 1. Grab the two characters that make up this byte
    // For index 0, this grabs string[0] and string[1]
    uint8_t high_nibble = hex_char_to_val(hex_string[i * 2]);
    uint8_t low_nibble = hex_char_to_val(hex_string[(i * 2) + 1]);

    // 2. Shift the high nibble 4 spots to the left, and merge them
    // Example: If high is 00001010 ('a') and low is 00001111 ('f')
    // (high << 4) becomes 10100000.
    // 10100000 | 00001111 becomes 10101111 (0xaf)
    out_binary[i] = (high_nibble << 4) | low_nibble;
  }
}

Signatures *signature = NULL;
size_t size = 0;

int load_signatures(const char *filename) {
  FILE *file = fopen(filename, "r");
  if (file == NULL) {
    printf("Could not load the file\n");
    return -1;
  }

  size_t capacity = 25;
  signature = (Signatures *)malloc(capacity * sizeof(Signatures));
  if (signature == NULL)
    return -1;

  char line[256];
  while (fgets(line, sizeof(line), file) != NULL) {
    if (strstr(line, "#") != NULL || strstr(line, "//"))
      continue;

    line[strcspn(line, "\n")] = 0;
    if (strlen(line) == 0)
      continue;

    char *name_token = strtok(line, ":");
    char *hash_token = strtok(NULL, "");

    if (name_token == NULL || hash_token == NULL)
      continue;

    while (*hash_token == ' ')
      hash_token++;

    int name_len = strlen(name_token);
    while (name_len > 0 && name_token[name_len - 1] == ' ') {
      name_token[name_len - 1] = '\0';
      name_len--;
    }

    if (size >= capacity) {
      capacity *= 2;
      signature =
          (Signatures *)realloc(signature, capacity * sizeof(Signatures));
    }

    strncpy(signature[size].name, name_token, sizeof(signature[size].name) - 1);
    signature[size].name[sizeof(signature[size].name) - 1] = '\0';

    hex_string_to_binary(hash_token, signature[size].hash);

    size++;
  }

  fclose(file);

  qsort(signature, size, sizeof(Signatures), compare_signatures);

  printf("All Signatures loaded sucessfully\n");
  return 0;
}

void binSearch_Signature(uint8_t hash[32], const char *filepath) {
  Signatures key;
  memcpy(key.hash, hash, 32);

  void *result =
      bsearch(&key, signature, size, sizeof(Signatures), compare_signatures);
  if (result != NULL) {
    Signatures *result_key = (Signatures *)result;
    printf("\033[1;31m[!] Malware Found:\033[0m\n");
    printf("Filepath : %s\n", filepath);
    printf("Match : %s\n\n", result_key->name);
    ;
  }
}

void free_Signatures() {
  if (signature != NULL)
    free(signature);
}
