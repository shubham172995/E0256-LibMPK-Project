# Minimal Makefile: build shared lib + main; keep objects in build/; no static .a, no extra mains
CC := gcc

# Prefer pkg-config for OpenSSL; fallback to Homebrew prefix or -lcrypto
PKG := $(shell (pkg-config --exists openssl && echo openssl) || (pkg-config --exists libcrypto && echo libcrypto) || true)
OPENSSL_DIR := $(shell brew --prefix openssl@3 2>/dev/null || true)

ifeq ($(PKG),)
  ifneq ($(OPENSSL_DIR),)
    OPENSSL_CFLAGS := -I$(OPENSSL_DIR)/include
    OPENSSL_LIBS   := -L$(OPENSSL_DIR)/lib -lcrypto
  else
    OPENSSL_CFLAGS :=
    OPENSSL_LIBS   := -lcrypto
  endif
else
  OPENSSL_CFLAGS := $(shell pkg-config --cflags $(PKG))
  OPENSSL_LIBS   := $(shell pkg-config --libs $(PKG))
endif

CFLAGS := -Iinclude -g -Wall $(OPENSSL_CFLAGS)

SRCDIR := src
OBJDIR := build

SRC_COMMON := $(SRCDIR)/trusted_crypto.c $(SRCDIR)/utilities.c $(SRCDIR)/envelope.c
MAIN_SRC := $(SRCDIR)/main.c

OBJS_COMMON := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRC_COMMON))
MAIN_OBJ := $(OBJDIR)/main.o

LIBNAME := trusted

UNAME_S := $(shell uname)
ifeq ($(UNAME_S),Darwin)
    SHARED_LIB := lib$(LIBNAME).dylib
    SHARED_LINK := -dynamiclib
    SHARED_EXTRA := -Wl,-install_name,@rpath/$(SHARED_LIB)
else
    SHARED_LIB := lib$(LIBNAME).so
    SHARED_LINK := -shared
    SHARED_EXTRA :=
endif

.PHONY: all clean

all: $(SHARED_LIB) main
	@echo "Built: $(SHARED_LIB) and main (objects in $(OBJDIR)/)"

# ensure build dir exists
$(OBJDIR):
	mkdir -p $(OBJDIR)

# compile common objects with -fPIC so they can go into shared lib
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

# compile main (no -fPIC necessary)
$(MAIN_OBJ): $(MAIN_SRC) | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# shared library: use the objects and link to OpenSSL so the .so contains the dependency
$(SHARED_LIB): $(OBJS_COMMON)
	$(CC) $(SHARED_LINK) -o $@ $^ $(OPENSSL_LIBS) $(SHARED_EXTRA)

# main executable linked to shared lib (main doesn't need -lcrypto)
# set rpath so the loader looks for the shared lib next to the binary
main: $(MAIN_OBJ) $(SHARED_LIB)
	$(CC) $(CFLAGS) -o $@ $(MAIN_OBJ) -L. -l$(LIBNAME) -Wl,-rpath,'$$ORIGIN'

clean:
	rm -rf $(OBJDIR) $(SHARED_LIB) main
