#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <relic.h>
#include <garble.h>

#define CA_HOST "127.0.0.1"
#define CA_PORT "8000"

#define g1_mul_norm(A, B, C) \
    { g1_mul(A, B, C); g1_norm(A, A); }
#define g1_mul_fix_norm(A, T, C)              \
    { g1_mul_fix(A, (const g1_t *) T, C); g1_norm(A, A); }
#define g1_sub_norm(A, B, C) \
    { g1_sub(A, B, C); g1_norm(A, A); }
#define g1_add_norm(A, B, C) \
    { g1_add(A, B, C); g1_norm(A, A); }
#define g2_mul_norm(A, B, C) \
    { g2_mul(A, B, C); g2_norm(A, A); }

size_t
g1_length_in_bytes_(g1_t e);
size_t
g2_length_in_bytes_(g2_t e);
size_t
g1_to_bytes_(uint8_t *buf, g1_t e);
size_t
g2_to_bytes_(uint8_t *buf, g2_t e);
size_t
bn_to_bytes_(uint64_t *buf, bn_t e);
size_t
g1_from_bytes_(g1_t e, uint8_t *buf);
size_t
g2_from_bytes_(g2_t e, uint8_t *buf);
size_t
bn_from_bytes_(bn_t e, uint64_t *buf);

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
hash(g1_t elem, int idx, bool bit);

block
commit(block in, block r);

typedef double abke_time_t;

double
get_time(void);

#endif
