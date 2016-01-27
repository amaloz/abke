#include "gc_comm.h"
#include "net.h"

int
gc_comm_send(int sock, GarbledCircuit *gc)
{
    net_send(sock, &gc->n, sizeof gc->n, 0);
    net_send(sock, &gc->m, sizeof gc->m, 0);
    net_send(sock, &gc->q, sizeof gc->q, 0);
    net_send(sock, &gc->r, sizeof gc->r, 0);
    net_send(sock, &gc->nFixedWires, sizeof gc->nFixedWires, 0);

    net_send(sock, gc->garbledGates, sizeof(GarbledGate) * gc->q, 0);
    net_send(sock, gc->garbledTable, sizeof(GarbledTable) * gc->q, 0);
    net_send(sock, gc->outputs, sizeof(int) * gc->m, 0);
    net_send(sock, gc->fixedWires, sizeof(FixedWire) * gc->nFixedWires, 0);
    net_send(sock, &gc->globalKey, sizeof(block), 0);

    return 0;
}

int
gc_comm_recv(int sock, GarbledCircuit *gc)
{
    net_recv(sock, &gc->n, sizeof gc->n, 0);
    net_recv(sock, &gc->m, sizeof gc->m, 0);
    net_recv(sock, &gc->q, sizeof gc->q, 0);
    net_recv(sock, &gc->r, sizeof gc->r, 0);
    net_recv(sock, &gc->nFixedWires, sizeof gc->nFixedWires, 0);

    gc->garbledGates = calloc(gc->q, sizeof(GarbledGate));
    gc->garbledTable = calloc(gc->q, sizeof(GarbledTable));
    gc->outputs = calloc(gc->m, sizeof(int));
    gc->fixedWires = calloc(gc->nFixedWires, sizeof(FixedWire));

    net_recv(sock, gc->garbledGates, sizeof(GarbledGate) * gc->q, 0);
    net_recv(sock, gc->garbledTable, sizeof(GarbledTable) * gc->q, 0);
    net_recv(sock, gc->outputs, sizeof(int) * gc->m, 0);
    net_recv(sock, gc->fixedWires, sizeof(FixedWire) * gc->nFixedWires, 0);
    net_recv(sock, &gc->globalKey, sizeof(block), 0);

    gc->wires = NULL;

    return 0;
}
