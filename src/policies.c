#include "policies.h"

#include "garble.h"
#include "circuits.h"
#include "gates.h"
#include "util.h"

#include <string.h>

void
build_AND_policy(garble_circuit *gc, int n, int q)
{
    garble_context ctxt;
    int *inputs, *outputs;
    int wire;
    int r;

    inputs = calloc(n, sizeof(int));
    outputs = calloc(n, sizeof(int));
    r = n + q;

    countToN(inputs, n);
    garble_new(gc, n, 1, q, r, GARBLE_TYPE);
    garble_start_building(gc, &ctxt);
    /* for (int layer = 0; layer < nlayers; ++layer) { */
    /*     for (int i = 0; i < n; i += 2) { */
    /*         int wire = getNextWire(&ctxt); */
    /*         ANDGate(gc, &ctxt, inputs[i], inputs[i + 1], wire); */
    /*         outputs[i] = outputs[i + 1] = wire; */
    /*     } */
    /*     memcpy(inputs, outputs, n * sizeof(int)); */
    /* } */
    ANDCircuit(gc, &ctxt, n, inputs, &wire);
    for (int i = n; i <= q; ++i) {
        int wire2 = garble_next_wire(&ctxt);
        garble_gate_AND(gc, wire, wire, wire2);
        wire = wire2;
    }
    garble_finish_building(gc, &wire);

    free(inputs);
    free(outputs);
}

