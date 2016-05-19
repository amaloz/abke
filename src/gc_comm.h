#ifndef GC_COMM_H
#define GC_COMM_H

#include "gc.h"

int
gc_comm_send(FILE *f, ExtGarbledCircuit *egc);
int
gc_comm_recv(FILE *f, ExtGarbledCircuit *egc);


#endif
