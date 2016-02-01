#include "policies.h"

#include "garble.h"
#include "circuits.h"
#include "gates.h"

void
build_AND_policy(GarbledCircuit *gc, int n)
{
    GarblingContext ctxt;
    int wire;
    int wires[n];
    int q = n - 1;
    int r = n + q;

    countToN(wires, n);

    createEmptyGarbledCircuit(gc, n, 1, q, r);
    startBuilding(gc, &ctxt);

    ANDCircuit(gc, &ctxt, n, wires, &wire);

    finishBuilding(gc, &wire);
}

