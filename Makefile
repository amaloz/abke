SRCDIR := src

SOURCES := $(wildcard $(SRCDIR)/*.c)
OBJECTS  := $(SOURCES:$(SRCDIR)/%.c=$(SRCDIR)/%.o)

INCLUDES := $(wildcard $(SRCDIR)/*.h)

CC=clang
CFLAGS=-O3 -Wall -Wextra -Isrc/ -I$(JUSTGARBLE)/include -maes -msse4 -march=native # -DPBC_DEBUG
LIBS=-lcrypto -lssl -lgmp -lpbc -lpthread -lgarble -lgarblec -L/usr/local/lib

all: main

main: $(OBJECTS)
	$(CC) $(SOURCES) $(LIBS) $(CFLAGS) 

PHONEY: clean
clean:
	rm -f $(SRCDIR)/*.o
	rm -f a.out

