#include "test.h"

#include "apse.h"
#include "util.h"

#include <openssl/rand.h>
#include "circuits.h"

static void
build_AND_circuit(GarbledCircuit *gc, int n)
{
    block inputLabels[2 * n];
    block outputLabels[n];
    GarblingContext ctxt;
    int wire;
    int wires[n];
    int q = n - 1;
    int r = n + q;

    countToN(wires, n);

    createInputLabels(inputLabels, n);
    createEmptyGarbledCircuit(gc, n, 1, q, r, inputLabels);
    startBuilding(gc, &ctxt);

    ANDCircuit(gc, &ctxt, n, wires, &wire);

    finishBuilding(gc, &ctxt, outputLabels, wires);
}

int
test_apse(void)
{
    struct apse_pp_t pp;
    struct apse_master_t master;
    struct apse_pk_t pk;
    struct apse_sk_t sk;
    struct apse_pk_t rpk;
    struct apse_sk_t rsk;
    int *attrs;
    struct apse_ctxt_t ctxt;
    element_t *inputs;
    element_t *ptxt;

    apse_pp_init(&pp, 1, PARAMFILE);
    apse_master_init(&pp, &master);
    apse_pk_init(&pp, &pk);
    apse_sk_init(&pp, &sk);
    apse_pk_init(&pp, &rpk);
    apse_sk_init(&pp, &rsk);
    apse_ctxt_init(&pp, &ctxt);
    attrs = calloc(pp.m, sizeof(int));
    ptxt = calloc(pp.m, sizeof(element_t));
    for (int i = 0; i < pp.m; ++i) {
        attrs[i] = 1;
        element_init_G1(ptxt[i], pp.pairing);
        
    }
    inputs = calloc(2 * pp.m, sizeof(element_t));
    for (int i = 0; i < 2 * pp.m; ++i) {
        element_init_G1(inputs[i], pp.pairing);
        element_random(inputs[i]);
    }

    apse_gen(&pp, &master, &pk, &sk, attrs);
    apse_unlink(&pp, &rpk, &rsk, &pk, &sk);
    if (!apse_vrfy(&pp, &master, &rpk)) {
        fprintf(stderr, "VERIFICATION FAILED\n");
        return -1;
    }
    apse_enc(&pp, &rpk, &ctxt, inputs, NULL);
    apse_dec(&pp, &rsk, ptxt, &ctxt, attrs);
    for (int i = 0; i < pp.m; ++i) {
        element_printf("%B\n%B\n%B\n\n", inputs[2 * i], inputs[2 * i + 1], ptxt[i]);
    }
    if (element_cmp(inputs[1], ptxt[0]) != 0) {
        fprintf(stderr, "DECRYPTION FAILED!\n");
        return -1;
    }

    return 0;
}

int
test_AND_circuit(int m)
{
    GarbledCircuit gc;
    block *inputs, *extracted, outputs[2], output;

    inputs = allocate_blocks(2 * m);
    extracted = allocate_blocks(m);
    for(int i = 0; i < 2 * m; ++i) {
        RAND_bytes((unsigned char *) &inputs[i], sizeof(block));
    }
    for (int i = 0; i < m; ++i) {
        extracted[i] = inputs[2 * i];
    }
    build_AND_circuit(&gc, m);
    garbleCircuit(&gc, inputs, outputs, GARBLE_TYPE_STANDARD);
    print_block(outputs[0]);
    printf(" ");
    print_block(outputs[1]);
    printf("\n");
    evaluate(&gc, extracted, &output, GARBLE_TYPE_STANDARD);
    print_block(output);
    printf("\n");
    return 0;
}
