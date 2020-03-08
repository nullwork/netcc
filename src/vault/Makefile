CC = clang
INCLUDES = 
DEFINES = -D_GNU_SOURCE
CFLAGS = -Weverything -Wno-unused-macros -Wno-padded -std=c11 -c $(DEFINES) $(INCLUDES)
BASEDIR = ../..
SRCDIR = .
OBJDIR = $(BASEDIR)/build/vault
SRCS = $(wildcard $(SRCDIR)/*.c)
OBJS = $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(SRCS))
LIB = $(BASEDIR)/lib/libvault.a

all: CFLAGS += -O2
all: lib
debug: CFLAGS += -g
debug: lib

lib: $(OBJS)
	ar rcs $(LIB) $(OBJS)

$(OBJDIR)/%.o : $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) $< -o $@

$(OBJDIR):
	mkdir -p $(OBJDIR)
