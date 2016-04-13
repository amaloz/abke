#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include <garble.h>

#define CA_HOST "127.0.0.1"
#define CA_PORT "8000"

#define element_length_in_bytes_ element_length_in_bytes
#define element_to_bytes_ element_to_bytes
#define element_from_bytes_ element_from_bytes

#define GARBLE_TYPE GARBLE_TYPE_PRIVACY_FREE

typedef unsigned long long mytime_t;

int
countToN(int *a, int N);

mytime_t
current_time(void);
mytime_t
median(mytime_t *values, int n);
double
doubleMean(double A[], int n);

size_t
filesize(const char *fname);

block
element_to_block(element_t elem);

block
commit(block in, block r);

typedef double abke_time_t;
#define get_time() pbc_get_time()

#endif
