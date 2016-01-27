#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include "justGarble.h"

#define PARAMFILE "a.param"

#define CA_HOST "127.0.0.1"
#define CA_PORT "8000"

block
element_to_block(element_t elem);

block
hash_block(block in);

typedef double abke_time_t;
#define get_time() pbc_get_time()

#endif
