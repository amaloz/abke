#ifndef ABKE_GC_H
#define ABKE_GC_H

#include "justGarble.h"

typedef struct {
    block map[2];
} translation_t;

typedef struct {
    GarbledCircuit gc;
    translation_t *translations;
} ExtGarbledCircuit;

#endif
