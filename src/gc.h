#ifndef ABKE_GC_H
#define ABKE_GC_H

#include "garble.h"

typedef struct {
    block map[2];
} label_map_t;

typedef struct {
    garble_circuit gc;
    label_map_t *map;
} ExtGarbledCircuit;

#endif
