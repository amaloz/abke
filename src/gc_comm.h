#ifndef GC_COMM_H
#define GC_COMM_H

#include "gc.h"

int
gc_comm_send(int sock, ExtGarbledCircuit *egc);
int
gc_comm_recv(int sock, ExtGarbledCircuit *egc);


#endif
