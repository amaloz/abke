AUTOMAKE_OPTIONS = foreign -Wall

MY_SOURCES = \
ase.c \
ase_homosig.c \
bls.c \
ca.c \
client.c \
gc_comm.c \
net.c \
policies.c \
server.c \
util.c

AM_CFLAGS = $(COMMON_CFLAGS) $(EXTRA_CFLAGS) -I$(top_srcdir) -I$(top_srcdir)/relic/include -g -maes -msse4 -march=native
AM_LDFLAGS = -L$(top_srcdir)/relic/lib -lcrypto -lssl -lgmp -lrelic -lgarble -lgarblec

bin_PROGRAMS = abke
abke_SOURCES  =  main.c $(MY_SOURCES)
