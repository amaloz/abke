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
buildCircuit(GarbledCircuit *gc)
{
    block inputLabels[2 * 2];
    block outputLabels[2];
    GarblingContext ctxt;
    int wire;
    int wires[2];
    int r = 3;
    int q = 1;

    countToN(wires, 2);

    createInputLabels(inputLabels, 2);
    createEmptyGarbledCircuit(gc, 2, 1, q, r, inputLabels);
    startBuilding(gc, &ctxt);

    for (int j = 0; j < 2; j += 2) {
        wire = getNextWire(&ctxt);
        ANDGate(gc, &ctxt, wires[j], wires[j+1], wire);
        wires[j] = wire;
    }

    finishBuilding(gc, &ctxt, outputLabels, wires);
}

static int
connect_to_ca(struct apse_pp_t *pp, struct apse_master_t *mpk)
{
    abke_time_t _start, _end;
    _start = get_time();
    {
        if (ca_info(pp, mpk, ROLE_SERVER, NULL, NULL, NULL) == -1) {
            fprintf(stderr, "Unable to connect to CA\n");
            return -1;
        }
    }
    _end = get_time();
    fprintf(stderr, "Get CA info: %f\n", _end - _start);
    return 0;
}

static int
server_garble(GarbledCircuit *gc, block *input_labels, block *output_labels)
{
    abke_time_t _start, _end;
    _start = get_time();
    {
        buildCircuit(gc);
        printf("Input labels:\n");
        for (int i = 0; i < gc->n; ++i) {
            printf("\t");
            print_block(input_labels[2 * i]);
            printf(" ");
            print_block(input_labels[2 * i + 1]);
            printf("\n");
        }
        garbleCircuit(gc, input_labels, output_labels, GARBLE_TYPE_STANDARD);
        printf("Output labels:\n");
        printf("\t");
        print_block(output_labels[0]);
        printf(" ");
        print_block(output_labels[1]);
        printf("\n");
    }
    _end = get_time();
    fprintf(stderr, "Garble circuit: %f\n", _end - _start);
    return 0;
}

static int
get_pk(struct apse_pp_t *pp, struct apse_master_t *mpk, struct apse_pk_t *pk,
       int fd)
{
    abke_time_t _start, _end;
    _start = get_time();
    {
        apse_pk_recv(pp, pk, fd);
        if (!apse_vrfy(pp, mpk, pk)) {
            fprintf(stderr, "pk fails to verify\n");
            return -1;
        }
    }
    _end = get_time();
    fprintf(stderr, "get randomized pk: %f\n", _end - _start);
    return 0;
}

static int
encrypt(struct apse_pp_t *pp, struct apse_pk_t *pk,
        struct apse_ctxt_elem_t *ctxts, element_t *inputs,
        unsigned int *seed)
{
    abke_time_t _start, _end;
    _start = get_time();
    {
        *seed = (unsigned int) rand(); /* XXX: TODO: FIXME: ah! insecure! */
        apse_enc(pp, pk, ctxts, inputs, seed);
    }
    _end = get_time();
    fprintf(stderr, "encrypt: %f\n", _end - _start);
    return 0;
}


int
server_go(const char *host, const char *port, int m)
{
    int sockfd = -1, fd = -1;
    block gc_seed, commitment;
    struct apse_pp_t pp;
    struct apse_master_t mpk;
    struct apse_pk_t client_pk;
    struct apse_ctxt_elem_t *ctxts;
    GarbledCircuit gc;
    element_t *inputs;
    block *input_labels, output_labels[2];
    unsigned int enc_seed;
    abke_time_t _start, _end;
    int res = -1;

    /* Initialization */
    _start = get_time();
    {
        gc_seed = seedRandom(NULL);
        apse_pp_init(&pp, m, PARAMFILE, NULL);
        apse_master_init(&pp, &mpk);
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
    }
    _end = get_time();
    fprintf(stderr, "Initialization: %f\n", _end - _start);

    res = connect_to_ca(&pp, &mpk);
    if (res == -1) goto cleanup;
    res = server_garble(&gc, input_labels, output_labels);
    if (res == -1) goto cleanup;

    /* Initialize server and accept connection from client */
    if ((sockfd = net_init_server(host, port)) == -1) {
        perror("net_init_server");
        exit(EXIT_FAILURE);
    }
    if ((fd = net_server_accept(sockfd)) == -1) {
        perror("net_server_accept");
        exit(EXIT_FAILURE);
    }

    res = get_pk(&pp, &mpk, &client_pk, fd);
    if (res == -1) goto cleanup;
    encrypt(&pp, &client_pk, ctxts, inputs, &enc_seed);
    if (res == -1) goto cleanup;

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
        block output_label, r, commitment2;
        net_recv(fd, &output_label, sizeof output_label, 0);
        net_recv(fd, &r, sizeof r, 0);
        printf("Received output label:\n\t");
        print_block(output_label);
        printf("\n");
        commitment2 = commit(output_label, r);
        if (unequal_blocks(commitment, commitment2)) {
            printf("CHEAT: commitments not equal\n");
            goto cleanup;
        }
        if (unequal_blocks(output_label, output_labels[1])) {
            printf("CHEAT: not 1-bit output label\n");
            goto cleanup;
        }
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

    removeGarbledCircuit(&gc);

    if (fd != -1)
        close(fd);
    if (sockfd != -1)
        close(sockfd);

    return res;
}
