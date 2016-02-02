#ifndef ABKE_GC_H
#define ABKE_GC_H

#include "justGarble.h"

typedef struct {
    block map[2];
} label_map_t;

typedef struct {
    GarbledCircuit gc;
    label_map_t *map;
} ExtGarbledCircuit;

#endif
