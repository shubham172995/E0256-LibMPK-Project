# Get Homebrew's OpenSSL path
OPENSSL_DIR := $(shell brew --prefix openssl@3)

# Include both local and OpenSSL headers
CFLAGS := -Iinclude -I$(OPENSSL_DIR)/include

# Link against OpenSSL's crypto library
LDFLAGS := -L$(OPENSSL_DIR)/lib -lcrypto

# Default target
main: src/main.c src/trusted_crypto.c include/trusted_crypto.h
	$(CC) -o main src/main.c src/trusted_crypto.c $(CFLAGS) $(LDFLAGS)
