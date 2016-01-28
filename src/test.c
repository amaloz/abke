#include "test.h"

#include "apse.h"
#include "util.h"

int
test_apse(void)
{
    struct apse_pp_t pp;
    struct apse_master_t master;
    struct apse_pk_t pk;
    struct apse_sk_t sk;
    int *attrs;
    struct apse_ctxt_elem_t *ctxt;
    element_t *inputs;
    element_t *ptxt;

    apse_pp_init(&pp, 1, PARAMFILE);
    apse_master_init(&pp, &master);
    apse_pk_init(&pp, &pk);
    apse_sk_init(&pp, &sk);
    attrs = calloc(pp.m, sizeof(int));
    ptxt = calloc(pp.m, sizeof(element_t));
    for (int i = 0; i < pp.m; ++i) {
        attrs[i] = 1;
        element_init_G1(ptxt[i], pp.pairing);
        
    }
    inputs = calloc(2 * pp.m, sizeof(element_t));
    ctxt = calloc(2 * pp.m, sizeof(struct apse_ctxt_elem_t));
    for (int i = 0; i < 2 * pp.m; ++i) {
        element_init_G1(inputs[i], pp.pairing);
        element_random(inputs[i]);
        element_init_G1(ctxt[i].ca, pp.pairing);
        element_init_G1(ctxt[i].cb, pp.pairing);
    }

    apse_gen(&pp, &master, &pk, &sk, attrs);
    apse_enc(&pp, &pk, ctxt, inputs, NULL);
    apse_dec(&pp, &sk, ptxt, ctxt, attrs);
    for (int i = 0; i < pp.m; ++i) {
        element_printf("%B\n%B\n%B\n\n", inputs[2 * i], inputs[2 * i + 1], ptxt[i]);
    }

    return 0;
}
