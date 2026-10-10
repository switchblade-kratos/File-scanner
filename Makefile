.RECIPEPREFIX = >
CC          = gcc
CFLAGS      = -Wall -Wextra -O2
DEBUG_FLAGS = -Wall -Wextra -g -fsanitize=address,undefined
SRC         = src/main.c src/scanner.c src/loader.c src/sha256.c
TARGET      = build/file-scanner

all: $(TARGET)

$(TARGET): $(SRC) $(wildcard src/*.h)
> mkdir -p build
> $(CC) $(CFLAGS) $(SRC) -o $(TARGET)

debug: $(SRC) $(wildcard src/*.h)
> mkdir -p build
> $(CC) $(DEBUG_FLAGS) $(SRC) -o $(TARGET)

clean:
> rm -rf build

.PHONY: all debug clean
