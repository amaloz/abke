#include "apse.h"
#include "ca.h"
#include "gc_comm.h"
#include "net.h"
#include "util.h"

#include <assert.h>
#include <unistd.h>
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
server_go(const char *host, const char *port, const int *attrs, int m)
{
    int sockfd = -1, fd = -1;
    block gc_seed, commitment;
    struct apse_pp_t pp;
    struct apse_master_t mpk;
    struct apse_pk_t client_pk;
    struct apse_ctxt_elem_t *ctxts;
    GarbledCircuit gc;
    element_t *inputs;
    block *input_labels;
    unsigned int enc_seed;
    abke_time_t _start, _end;
    int res = -1;

    struct apse_pk_t pk;
    struct apse_sk_t sk;

    /* Initialization */
    _start = get_time();
    {
        gc_seed = seedRandom(NULL);
        apse_pp_init(&pp, m, PARAMFILE, NULL);
        apse_master_init(&pp, &mpk);
        apse_pk_init(&pp, &pk);
        apse_sk_init(&pp, &sk);
        apse_pk_init(&pp, &client_pk);
        inputs = calloc(2 * pp.m, sizeof(element_t));
        input_labels = calloc(2 * pp.m, sizeof(block));
        ctxts = calloc(2 * pp.m, sizeof(struct apse_ctxt_elem_t));
        for (int i = 0; i < 2 * pp.m; ++i) {
            element_init_G1(inputs[i], pp.pairing);
            element_random(inputs[i]);
            input_labels[i] = element_to_block(inputs[i]);
            element_init_G1(ctxts[i].ca, pp.pairing);
            element_init_G1(ctxts[i].cb, pp.pairing);
        }
        /* for (int i = 0; i < pp.m; ++i) { */
        /*     element_printf("%B\n%B\n\n", inputs[2 * i], inputs[2 * i + 1]); */
        /* } */
        /* for (int i = 0; i < pp.m; ++i) { */
        /*     print_block(input_labels[2 * i]); */
        /*     printf(" "); */
        /*     print_block(input_labels[2 * i + 1]); */
        /*     printf("\n"); */
        /* } */
    }
    _end = get_time();
    fprintf(stderr, "Initialization: %f\n", _end - _start);

    /* Connect to CA */
    _start = get_time();
    {
        if (ca_info(&pp, &mpk, &pk, &sk, attrs) == -1) {
            fprintf(stderr, "Unable to connect to CA\n");
            goto cleanup;
        }
    }
    _end = get_time();
    fprintf(stderr, "Get CA info: %f\n", _end - _start);

    /* Garble circuit */
    _start = get_time();
    {
        buildCircuit(&gc, pp.m, 1);
        garbleCircuit(&gc, input_labels, NULL, GARBLE_TYPE_STANDARD);
    }
    _end = get_time();
    fprintf(stderr, "Garble circuit: %f\n", _end - _start);

    /* Initialize server and accept connection from client */
    if ((sockfd = net_init_server(host, port)) == -1) {
        perror("net_init_server");
        exit(EXIT_FAILURE);
    }
    if ((fd = net_server_accept(sockfd)) == -1) {
        perror("net_server_accept");
        exit(EXIT_FAILURE);
    }

    /* Get randomized pk from client */
    _start = get_time();
    {
        apse_pk_recv(&pp, &client_pk, fd);
        if (!apse_vrfy(&pp, &mpk, &client_pk)) {
            fprintf(stderr, "pk fails to verify\n");
            goto cleanup;
        }
    }
    _end = get_time();
    fprintf(stderr, "get randomized pk: %f\n", _end - _start);

    /* Encrypt GC input labels */
    _start = get_time();
    {
        enc_seed = (unsigned int) rand(); /* XXX: TODO: FIXME: ah! */
        apse_enc(&pp, &client_pk, ctxts, inputs, &enc_seed);
    }
    _end = get_time();
    fprintf(stderr, "encrypt: %f\n", _end - _start);

    /* Send ciphertext and GC to client */
    _start = get_time();
    {
        for (int i = 0; i < 2 * pp.m; ++i) {
            net_send_element(fd, ctxts[i].ca);
            net_send_element(fd, ctxts[i].cb);
        }
        gc_comm_send(fd, &gc);
    }
    _end = get_time();
    fprintf(stderr, "send ctxt/gc: %f\n", _end - _start);

    /* Receive commitment from client */
    _start = get_time();
    {
        net_recv(fd, &commitment, sizeof commitment, 0);
    }
    _end = get_time();
    fprintf(stderr, "receive commitment: %f\n", _end - _start);

    /* Send randomness and inputs to client */
    _start = get_time();
    {
        net_send(fd, &gc_seed, sizeof gc_seed, 0);
        net_send(fd, &enc_seed, sizeof enc_seed, 0);
        for (int i = 0; i < 2 * pp.m; ++i) {
            net_send_element(fd, inputs[i]);
        }
    }
    _end = get_time();
    fprintf(stderr, "send randomness/input labels: %f\n", _end - _start);

    {
        block output_label;
        net_recv(fd, &output_label, sizeof output_label, 0);
        /* TODO: check equality */
    }

    fprintf(stderr, "DO COIN TOSSING!\n");

    res = 0;

cleanup:
    for (int i = 0; i < 2 * m; ++i) {
        element_clear(inputs[i]);
        element_clear(ctxts[i].ca);
        element_clear(ctxts[i].cb);
    }
    free(inputs);
    free(ctxts);
    free(input_labels);

    apse_pk_clear(&pp, &client_pk);
    apse_master_clear(&pp, &mpk);
    apse_pp_clear(&pp);

    if (fd != -1)
        close(fd);
    if (sockfd != -1)
        close(sockfd);

    return res;
}
