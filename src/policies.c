#include "policies.h"

#include <garble.h>
#include <circuits.h>
#include <gates.h>
#include "util.h"

#include <string.h>

void
build_AND_policy(garble_circuit *gc, uint64_t n, uint64_t q)
{
    garble_context ctxt;
    int *inputs, *outputs;
    int wire;

    inputs = calloc(n, sizeof(int));
    outputs = calloc(n, sizeof(int));

    countToN(inputs, n);
    garble_new(gc, n, 1, GARBLE_TYPE);
    garble_start_building(gc, &ctxt);
    ANDCircuit(gc, &ctxt, n, inputs, &wire);
    for (uint64_t i = n; i <= q; ++i) {
        int wire2 = garble_next_wire(&ctxt);
        garble_gate_AND(gc, &ctxt, wire, wire, wire2);
        wire = wire2;
    }
    garble_finish_building(gc, &ctxt, &wire);

    free(inputs);
    free(outputs);
}

