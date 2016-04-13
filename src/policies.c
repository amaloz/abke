#include "policies.h"
#include "util.h"

#include <garble.h>
#include <circuits.h>
#include <circuit_builder.h>


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
    builder_start_building(gc, &ctxt);
    circuit_and(gc, &ctxt, n, inputs, &wire);
    for (uint64_t i = n; i <= q; ++i) {
        int wire2 = builder_next_wire(&ctxt);
        gate_AND(gc, &ctxt, wire, wire, wire2);
        wire = wire2;
    }
    builder_finish_building(gc, &ctxt, &wire);

    free(inputs);
    free(outputs);
}

