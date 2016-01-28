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
connect_to_ca(struct apse_pp_t *pp, struct apse_master_t *mpk,
              struct apse_pk_t *pk, struct apse_sk_t *sk, const int *attrs)
{
    abke_time_t _start, _end;
    _start = get_time();
    {
        if (ca_info(pp, mpk, ROLE_CLIENT, pk, sk, attrs) == -1) {
            fprintf(stderr, "ERROR: Unable to connect to CA\n");
            return -1;
        }
    }
    _end = get_time();
    fprintf(stderr, "Get CA info: %f\n", _end - _start);
    return 0;
}

static int
decrypt(struct apse_pp_t *pp, struct apse_sk_t *sk,
        struct apse_ctxt_elem_t *ctxts, element_t *inputs, block *input_labels,
        const int *attrs)
{
    abke_time_t _start, _end;
    _start = get_time();
    {
        apse_dec(pp, sk, inputs, ctxts, attrs);
        printf("Input labels:\n");
        for (int i = 0; i < pp->m; ++i) {
            input_labels[i] = element_to_block(inputs[i]);
            printf("\t");
            print_block(input_labels[i]);
            printf("\n");
        }
    }
    _end = get_time();
    fprintf(stderr, "Decrypt: %f\n", _end - _start);
    return 0;
}

static int
check(struct apse_pp_t *pp, struct apse_pk_t *pk, GarbledCircuit *gc,
      struct apse_ctxt_elem_t *ctxts, int fd)
{
    int res = -1;
    abke_time_t _start, _end;
    _start = get_time();
    {
        GarbledCircuit gc2;
        unsigned char gc_hash[SHA_DIGEST_LENGTH];
        struct apse_ctxt_elem_t *claimed_ctxts;
        element_t *claimed_inputs;
        block *claimed_input_labels;
        block gc_seed;
        unsigned int enc_seed;

        claimed_ctxts = calloc(2 * pp->m, sizeof(struct apse_ctxt_elem_t));
        claimed_inputs = calloc(2 * pp->m, sizeof(element_t));
        for (int i = 0; i < 2 * pp->m; ++i) {
            element_init_G1(claimed_ctxts[i].ca, pp->pairing);
            element_init_G1(claimed_ctxts[i].cb, pp->pairing);
            element_init_G1(claimed_inputs[i], pp->pairing);
        }
        claimed_input_labels = calloc(2 * pp->m, sizeof(block));

        net_recv(fd, &gc_seed, sizeof gc_seed, 0);
        net_recv(fd, &enc_seed, sizeof enc_seed, 0);

        /* Receive the inputs from the server, and re-encrypt to verify that
         * the ciphertexts sent earlier are indeed correct */
        for (int i = 0; i < 2 * pp->m; ++i) {
            net_recv_element(fd, claimed_inputs[i]);
            claimed_input_labels[i] = element_to_block(claimed_inputs[i]);
        }
        apse_enc(pp, pk, claimed_ctxts, claimed_inputs, &enc_seed);
        for (int i = 0; i < 2 * pp->m; ++i) {
            if (element_cmp(claimed_ctxts[i].ca, ctxts[i].ca)
                || element_cmp(claimed_ctxts[i].cb, ctxts[i].cb)) {
                printf("CHEAT: input %d doesn't check out\n", i);
                goto cleanup;
            }
        }

        /* Regarble the circuit to verify that it was constructed correctly */
        hashGarbledCircuit(gc, gc_hash, GARBLE_TYPE_STANDARD);
        (void) seedRandom(&gc_seed);
        buildCircuit(&gc2);
        garbleCircuit(&gc2, claimed_input_labels, NULL, GARBLE_TYPE_STANDARD);
        if (checkGarbledCircuit(&gc2, gc_hash, GARBLE_TYPE_STANDARD) != 0) {
            printf("CHEAT: GCs don't check out\n");
            goto cleanup;
        }
        res = 0;
        
    cleanup:
        for (int i = 0; i < 2 * pp->m; ++i) {
            element_clear(claimed_ctxts[i].ca);
            element_clear(claimed_ctxts[i].cb);
            element_clear(claimed_inputs[i]);
        }
        free(claimed_ctxts);
        free(claimed_inputs);
        free(claimed_input_labels);

        removeGarbledCircuit(&gc2);
    }
    _end = get_time();
    fprintf(stderr, "Check: %f\n", _end - _start);
    return res;
}

int
client_go(const char *host, const char *port, const int *attrs, int m)
{
    int fd = -1;
    struct apse_pp_t pp;
    struct apse_master_t mpk;
    struct apse_pk_t pk, rpk;
    struct apse_sk_t sk, rsk;

    GarbledCircuit gc;

    element_t *inputs;
    block *input_labels;
    struct apse_ctxt_elem_t *ctxts;

    block output_label = zero_block(), commitment, r;

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
        input_labels = allocate_blocks(pp.m);
        for (int i = 0; i < pp.m; ++i) {
            element_init_G1(inputs[i], pp.pairing);
            input_labels[i] = zero_block();
        }
        ctxts = calloc(2 * pp.m, sizeof(struct apse_ctxt_elem_t));
        for (int i = 0; i < 2 * pp.m; ++i) {
            element_init_G1(ctxts[i].ca, pp.pairing);
            element_init_G1(ctxts[i].cb, pp.pairing);
        }

    }
    _end = get_time();
    fprintf(stderr, "Initialization: %f\n", _end - _start);

    res = connect_to_ca(&pp, &mpk, &pk, &sk, attrs);
    if (res == -1) goto cleanup;

    /* Connect to server */
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
    }
    _end = get_time();
    fprintf(stderr, "Send pk: %f\n", _end - _start);

    _start = get_time();
    {
        for (int i = 0; i < 2 * pp.m; ++i) {
            net_recv_element(fd, ctxts[i].ca);
            net_recv_element(fd, ctxts[i].cb);
        }
        gc_comm_recv(fd, &gc);
    }
    _end = get_time();
    fprintf(stderr, "receive ctxt/gc: %f\n", _end - _start);

    res = decrypt(&pp, &sk, ctxts, inputs, input_labels, attrs);
    if (res == -1) goto cleanup;

    _start = get_time();
    {
        /* block output_label; */
        evaluate(&gc, input_labels, &output_label, GARBLE_TYPE_STANDARD);
        printf("Output label:\n\t");
        print_block(output_label);
        printf("\n");
    }
    _end = get_time();
    fprintf(stderr, "Evaluate GC: %f\n", _end - _start);

    _start = get_time();
    {
        /* Need seedRandom() for randomBlock() */
        (void) seedRandom(NULL);
        r = randomBlock();
        commitment = commit(output_label, r);
        net_send(fd, &commitment, sizeof commitment, 0);
    }
    _end = get_time();
    fprintf(stderr, "Compute and send commitment: %f\n", _end - _start);

    res = check(&pp, &pk, &gc, ctxts, fd);
    if (res == -1) goto cleanup;
    net_send(fd, &output_label, sizeof output_label, 0);
    net_send(fd, &r, sizeof r, 0);

    fprintf(stderr, "DO COIN TOSSING!\n");

    res = 0;

cleanup:
    for (int i = 0; i < 2 * pp.m; ++i) {
        element_clear(ctxts[i].ca);
        element_clear(ctxts[i].cb);
    }
    for (int i = 0; i < pp.m; ++i) {
        element_clear(inputs[i]);
    }
    free(ctxts);
    free(inputs);
    free(input_labels);

    apse_sk_clear(&pp, &rsk);
    apse_pk_clear(&pp, &rpk);
    apse_sk_clear(&pp, &sk);
    apse_pk_clear(&pp, &pk);
    apse_master_clear(&pp, &mpk);
    apse_pp_clear(&pp);

    removeGarbledCircuit(&gc);

    if (fd != -1)
        close(fd);

    return res;
}
