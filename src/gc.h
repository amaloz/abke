#ifndef ABKE_GC_H
#define ABKE_GC_H

#include "garble.h"

typedef struct {
    garble_circuit gc;
    block *ttables;
} ExtGarbledCircuit;

#endif
