SRCDIR := src

JUSTGARBLE = JustGarble
SOURCES := $(wildcard $(SRCDIR)/*.c)
OBJECTS  := $(SOURCES:$(SRCDIR)/%.c=$(SRCDIR)/%.o)

JUSTGARBLESRC := $(wildcard $(JUSTGARBLE)/src/*.c)

INCLUDES := $(wildcard $(SRCDIR)/*.h)

CC=gcc
CFLAGS=-g -Wall -I$(JUSTGARBLE)/include -maes -msse4 -march=native
LIBS=-lmsgpackc -lm -lcrypto -lssl -lgmp -lpbc

all: main

main: $(OBJECTS)
	$(CC) $(SOURCES) $(JUSTGARBLESRC) $(LIBS) $(CFLAGS) 

PHONEY: clean
clean:
	rm -f $(SRCDIR)/*.o
	rm -f a.out

