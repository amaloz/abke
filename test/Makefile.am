AM_CFLAGS = $(COMMON_CFLAGS) $(EXTRA_CFLAGS) -I$(top_srcdir)/src -I$(top_srcdir)/relic/include -maes -msse4 -march=native
AM_LDFLAGS = -L$(top_srcdir)/relic/lib -lcrypto -lssl -lgmp -lrelic -lgarble -lgarblec

MY_SOURCES = \
../src/ase.c \
../src/ase_homosig.c \
../src/bls.c \
../src/ca.c \
../src/client.c \
../src/gc_comm.c \
../src/net.c \
../src/policies.c \
../src/server.c \
../src/util.c

check_PROGRAMS = test

TESTS = $(check_PROGRAMS)

test_SOURCES = test.c $(MY_SOURCES)
