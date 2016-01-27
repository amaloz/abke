#ifndef GC_COMM_H
#define GC_COMM_H

#include "justGarble.h"

int
gc_comm_send(int sock, GarbledCircuit *gc);
int
gc_comm_recv(int sock, GarbledCircuit *gc);


#endif
