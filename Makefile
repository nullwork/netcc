CC = clang
INCLUDES = -Isrc
DEFINES = -D_GNU_SOURCE
CFLAGS = -Weverything -Wno-unused-macros -Wno-padded -std=c11 -c $(DEFINES) $(INCLUDES)
LDFLAGS = -levent -lseccomp -Llib -lvault
SRCDIR = src
OBJDIR = build
SRCS = $(wildcard $(SRCDIR)/*.c)
OBJS = $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(SRCS))
EXECUTABLE = bin/netcc

all: CFLAGS += -O2
all: main
debug: CFLAGS += -g
debug: main

main: vault $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $(EXECUTABLE)

vault:
	$(MAKE) -C src/vault $(MAKECMDGOALS)

$(OBJDIR)/%.o : $(SRCDIR)/%.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf build/*
	rm -rf lib/*
