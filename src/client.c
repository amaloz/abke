#include "apse.h"
#include "ca.h"
#include "gc_comm.h"
#include "net.h"
#include "util.h"

#include <assert.h>
#include <unistd.h>
#include <openssl/sha.h>
#include "garble.h"
#include "gates.h"

static void
buildCircuit(GarbledCircuit *gc, int n, int nlayers)
{
    block inputLabels[2 * n];
    block outputLabels[n];
    GarblingContext ctxt;
    int wire;
    int wires[n];
    int r = n + n / 2 * nlayers;
    int q = n / 2 * nlayers;

    countToN(wires, n);

    createInputLabels(inputLabels, n);
    createEmptyGarbledCircuit(gc, n, n, q, r, inputLabels);
    startBuilding(gc, &ctxt);

    for (int i = 0; i < nlayers; ++i) {
        for (int j = 0; j < n; j += 2) {
            wire = getNextWire(&ctxt);
            ANDGate(gc, &ctxt, wires[j], wires[j+1], wire);
            wires[j] = wires[j+1] = wire;
        }
    }

    finishBuilding(gc, &ctxt, outputLabels, wires);
}

int
client_go(const char *host, const char *port, const int *attrs, int m)
{
    int fd = -1;
    struct apse_pp_t pp;
    struct apse_master_t mpk;
    struct apse_pk_t pk, rpk;
    struct apse_sk_t sk, rsk;
    struct apse_ctxt_elem_t *ctxt;
    GarbledCircuit gc;
    element_t *inputs, *claimed_inputs;
    block *input_labels, *claimed_input_labels;
    block output_label, commitment, gc_seed;
    unsigned int enc_seed;
    abke_time_t _start, _end;
    int res = -1;

    _start = get_time();
    {
        apse_pp_init(&pp, m, PARAMFILE, NULL);
        apse_master_init(&pp, &mpk);
        apse_pk_init(&pp, &pk);
        apse_sk_init(&pp, &sk);
        apse_pk_init(&pp, &rpk);
        apse_sk_init(&pp, &rsk);
        inputs = calloc(pp.m, sizeof(element_t));
        for (int i = 0; i < pp.m; ++i) {
            element_init_G1(inputs[i], pp.pairing);
        }
        input_labels = allocate_blocks(pp.m);
        claimed_inputs = calloc(2 * pp.m, sizeof(element_t));
        ctxt = calloc(2 * pp.m, sizeof(struct apse_ctxt_elem_t));
        for (int i = 0; i < 2 * pp.m; ++i) {
            element_init_G1(claimed_inputs[i], pp.pairing);
            element_init_G1(ctxt[i].ca, pp.pairing);
            element_init_G1(ctxt[i].cb, pp.pairing);
        }
        claimed_input_labels = calloc(2 * pp.m, sizeof(block));
    }
    _end = get_time();
    fprintf(stderr, "Initialization: %f\n", _end - _start);

    _start = get_time();
    {
        if (ca_info(&pp, &mpk, &pk, &sk, attrs) == -1) {
            fprintf(stderr, "Unable to connect to CA\n");
            goto cleanup;
        }
    }
    _end = get_time();
    fprintf(stderr, "Get CA info: %f\n", _end - _start);

    if ((fd = net_init_client(host, port)) == -1) {
        perror("net_init_client");
        goto cleanup;
    }

    _start = get_time();
    {
        /* XXX: doesn't work yet */
        /* apse_unlink(&pp, &rpk, &rsk, &pk, &sk); */
    }
    _end = get_time();
    fprintf(stderr, "Randomize pk: %f\n", _end - _start);

    _start = get_time();
    {
        apse_pk_send(&pp, &pk, fd);
        for (int i = 0; i < 2 * pp.m; ++i) {
            net_recv_element(fd, ctxt[i].ca);
            net_recv_element(fd, ctxt[i].cb);
        }
        gc_comm_recv(fd, &gc);
    }
    _end = get_time();
    fprintf(stderr, "Send pk, receive ctxt/gc: %f\n", _end - _start);

    _start = get_time();
    {
        apse_dec(&pp, &sk, inputs, ctxt, attrs);
        /* for (int i = 0; i < pp.m; ++i) { */
        /*     element_printf("%B\n\n", inputs[i]); */
        /* } */
        /* for (int i = 0; i < pp.m; ++i) { */
        /*     input_labels[i] = element_to_block(inputs[i]); */
        /*     print_block(input_labels[i]); */
        /*     printf("\n"); */
        /* } */
    }
    _end = get_time();
    fprintf(stderr, "Decrypt: %f\n", _end - _start);

    _start = get_time();
    {
        evaluate(&gc, input_labels, &output_label, GARBLE_TYPE_STANDARD);
    }
    _end = get_time();
    fprintf(stderr, "Evaluate GC: %f\n", _end - _start);

    _start = get_time();
    {
        commitment = hash_block(output_label);
        net_send(fd, &commitment, sizeof commitment, 0);
    }
    _end = get_time();
    fprintf(stderr, "Compute and send hash: %f\n", _end - _start);

    {
        GarbledCircuit gc2;
        unsigned char gc_hash[SHA_DIGEST_LENGTH];

        claimed_inputs = calloc(2 * pp.m, sizeof(element_t));
        for (int i = 0; i < 2 * m; ++i) {
            element_init_G1(claimed_inputs[i], pp.pairing);
        }
        net_recv(fd, &gc_seed, sizeof gc_seed, 0);
        net_recv(fd, &enc_seed, sizeof enc_seed, 0);
        for (int i = 0; i < 2 * m; ++i) {
            net_recv_element(fd, claimed_inputs[i]);
            claimed_input_labels[i] = element_to_block(claimed_inputs[i]);
        }
        /* TODO: Check claimed inputs! */
        
        hashGarbledCircuit(&gc, gc_hash, GARBLE_TYPE_STANDARD);
        (void) seedRandom(&gc_seed);
        buildCircuit(&gc2, pp.m, 1);
        garbleCircuit(&gc2, claimed_input_labels, NULL, GARBLE_TYPE_STANDARD);
        if (checkGarbledCircuit(&gc2, gc_hash, GARBLE_TYPE_STANDARD) != 0) {
            fprintf(stderr, "GCs don't check out\n");
            goto cleanup;
        }
        net_send(fd, &output_label, sizeof output_label, 0);
    }

    fprintf(stderr, "DO COIN TOSSING!\n");

    res = 0;

cleanup:
    for (int i = 0; i < 2 * pp.m; ++i) {
        element_clear(ctxt[i].ca);
        element_clear(ctxt[i].cb);
        element_clear(claimed_inputs[i]);
    }
    for (int i = 0; i < pp.m; ++i) {
        element_clear(inputs[i]);
    }
    free(ctxt);
    free(inputs);
    free(claimed_inputs);
    free(input_labels);

    apse_sk_clear(&pp, &rsk);
    apse_pk_clear(&pp, &rpk);
    apse_sk_clear(&pp, &sk);
    apse_pk_clear(&pp, &pk);
    apse_master_clear(&pp, &mpk);
    apse_pp_clear(&pp);

    if (fd != -1)
        close(fd);

    return res;
}
