#include "loader.h"
#include <ctype.h>
#include <errno.h>
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

static Signatures *signature = NULL;
static size_t signature_count = 0;

// Returns 1 if s is exactly 64 hex characters, else 0
static int is_valid_hash(const char *s) {
  if (strlen(s) != 64)
    return 0;
  for (int i = 0; i < 64; i++) {
    if (!isxdigit((unsigned char)s[i]))
      return 0;
  }
  return 1;
}

int load_signatures(const char *filename) {
  FILE *file = fopen(filename, "r");
  if (file == NULL) {
    fprintf(stderr, "Could not open %s: %s\n", filename, strerror(errno));
    return -1;
  }

  size_t capacity = 25;
  signature = malloc(capacity * sizeof(Signatures));
  if (signature == NULL) {
    fclose(file);
    return -1;
  }
  signature_count = 0;

  char line[256];
  size_t line_no = 0;
  size_t skipped = 0;

  while (fgets(line, sizeof(line), file) != NULL) {
    line_no++;

    // Line too long for the buffer: throw away the rest of it
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] != '\n' && !feof(file)) {
      int c;
      while ((c = fgetc(file)) != '\n' && c != EOF)
        ;
      fprintf(stderr, "Warning: line %zu is too long, skipped\n", line_no);
      skipped++;
      continue;
    }

    // Strip \n and \r (handles Windows line endings)
    line[strcspn(line, "\r\n")] = '\0';

    // Skip leading whitespace, then blank lines and comments
    char *start = line;
    while (*start == ' ' || *start == '\t')
      start++;
    if (*start == '\0' || *start == '#' || strncmp(start, "//", 2) == 0)
      continue;

    char *name_token = strtok(start, ":");
    char *hash_token = strtok(NULL, "");
    if (name_token == NULL || hash_token == NULL) {
      fprintf(stderr, "Warning: line %zu has no 'name: hash' format, skipped\n",
              line_no);
      skipped++;
      continue;
    }

    // Trim spaces around the hash
    while (*hash_token == ' ' || *hash_token == '\t')
      hash_token++;
    size_t hash_len = strlen(hash_token);
    while (hash_len > 0 && (hash_token[hash_len - 1] == ' ' ||
                            hash_token[hash_len - 1] == '\t')) {
      hash_token[--hash_len] = '\0';
    }

    // Trim trailing spaces from the name
    size_t name_len = strlen(name_token);
    while (name_len > 0 && (name_token[name_len - 1] == ' ' ||
                            name_token[name_len - 1] == '\t')) {
      name_token[--name_len] = '\0';
    }

    if (!is_valid_hash(hash_token)) {
      fprintf(stderr,
              "Warning: line %zu has an invalid SHA-256 hash, skipped\n",
              line_no);
      skipped++;
      continue;
    }

    // Grow the array if needed, without losing the old pointer on failure
    if (signature_count >= capacity) {
      size_t new_capacity = capacity * 2;
      Signatures *tmp = realloc(signature, new_capacity * sizeof(Signatures));
      if (tmp == NULL) {
        fprintf(stderr, "Error: out of memory while loading signatures\n");
        fclose(file);
        free(signature);
        signature = NULL;
        signature_count = 0;
        return -1;
      }
      signature = tmp;
      capacity = new_capacity;
    }

    strncpy(signature[signature_count].name, name_token,
            sizeof(signature[signature_count].name) - 1);
    signature[signature_count]
        .name[sizeof(signature[signature_count].name) - 1] = '\0';
    hex_string_to_binary(hash_token, signature[signature_count].hash);
    signature_count++;
  }

  fclose(file);

  qsort(signature, signature_count, sizeof(Signatures), compare_signatures);

  printf("Loaded %zu signatures (%zu lines skipped)\n", signature_count,
         skipped);
  return 0;
}

int binSearch_Signature(uint8_t hash[32], const char *filepath) {
  Signatures key;
  memcpy(key.hash, hash, 32);

  Signatures *result = bsearch(&key, signature, signature_count,
                               sizeof(Signatures), compare_signatures);
  if (result != NULL) {
    printf("\033[1;31m[!] Malware Found:\033[0m\n");
    printf("Filepath : %s\n", filepath);
    printf("Match : %s\n\n", result->name);
    return 1;
  }
  return 0;
}

void free_Signatures(void) {
  free(signature);
  signature = NULL;
  signature_count = 0;
}
