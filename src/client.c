#include "apse.h"
#include "ca.h"
#include "gc_comm.h"
#include "net.h"
#include "util.h"

#include <assert.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include "garble.h"
#include "circuits.h"
#include "gates.h"

static void
buildCircuit(GarbledCircuit *gc, int n)
{
    block inputLabels[2 * n];
    block outputLabels[n];
    GarblingContext ctxt;
    int wire;
    int wires[n];
    int r = n + n / 2;
    int q = n - 1;

    countToN(wires, n);

    createInputLabels(inputLabels, n);
    createEmptyGarbledCircuit(gc, n, 1, q, r, inputLabels);
    startBuilding(gc, &ctxt);

    wire = getNextWire(&ctxt);
    ANDGate(gc, &ctxt, wires[0], wires[1], wire);
    /* ANDCircuit(gc, &ctxt, n, wires, &wire); */

    finishBuilding(gc, &ctxt, outputLabels, wires);
}

static int
_connect_to_ca(struct apse_pp_t *pp, struct apse_master_t *mpk,
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
_decrypt(struct apse_pp_t *pp, struct apse_sk_t *sk,
         struct apse_ctxt_elem_t *ctxts, block *input_labels,
         const int *attrs, abke_time_t *total)
{
    abke_time_t _start, _end;
    _start = get_time();
    {
        element_t *inputs;

        inputs = calloc(pp->m, sizeof(element_t));
        for (int i = 0; i < pp->m; ++i) {
            element_init_G1(inputs[i], pp->pairing);
        }
        apse_dec(pp, sk, inputs, ctxts, attrs);
        for (int i = 0; i < pp->m; ++i) {
            input_labels[i] = element_to_block(inputs[i]);
            element_clear(inputs[i]);
        }
        free(inputs);
    }
    _end = get_time();
    fprintf(stderr, "Decrypt: %f\n", _end - _start);
    if (total)
        *total += _end - _start;
    return 0;
}
static int
_evaluate(GarbledCircuit *gc, const block *input_labels, block *output_label,
          abke_time_t *total)
{
    abke_time_t _start, _end;
    _start = get_time();
    {
        evaluate(gc, input_labels, output_label, GARBLE_TYPE_STANDARD);
    }
    _end = get_time();
    fprintf(stderr, "Evaluate GC: %f\n", _end - _start);
    if (total)
        *total += _end - _start;
    return 0;
}

static int
_commit(block label, block *r, int fd, abke_time_t *total)
{
    abke_time_t _start, _end;
    _start = get_time();
    {
        block commitment;

        /* Need seedRandom() for randomBlock() */
        (void) seedRandom(NULL);
        if (RAND_bytes((unsigned char *) r, sizeof(block)) == 0) {
            fprintf(stderr, "RAND_bytes failed\n");
            return -1;
        }
        commitment = commit(label, *r);
        net_send(fd, &commitment, sizeof commitment, 0);
    }
    _end = get_time();
    fprintf(stderr, "Compute and send commitment: %f\n", _end - _start);
    if (total)
        *total += _end - _start;
    return 0;
}

static int
_check(struct apse_pp_t *pp, struct apse_pk_t *pk, GarbledCircuit *gc,
       struct apse_ctxt_elem_t *ctxts, int fd, abke_time_t *total)
{
    int res = -1;
    abke_time_t _start, _end;
    _start = get_time();
    {
        GarbledCircuit gc2;
        int gc_built = 0;
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
        claimed_input_labels = allocate_blocks(2 * pp->m);

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
        buildCircuit(&gc2, pp->m);
        garbleCircuit(&gc2, claimed_input_labels, NULL, GARBLE_TYPE_STANDARD);
        gc_built = 1;
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

        if (gc_built)
            removeGarbledCircuit(&gc2);
    }
    _end = get_time();
    fprintf(stderr, "Check: %f\n", _end - _start);
    if (total)
        *total += _end - _start;
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
    block key;

    GarbledCircuit gc;
    int gc_built = 0;

    struct apse_ctxt_elem_t *ctxts;

    abke_time_t _start, _end, total = 0.0;
    int res = -1;

    _start = get_time();
    {
        apse_pp_init(&pp, m, PARAMFILE);
        apse_master_init(&pp, &mpk);
        apse_pk_init(&pp, &pk);
        apse_sk_init(&pp, &sk);
        apse_pk_init(&pp, &rpk);
        apse_sk_init(&pp, &rsk);
        ctxts = calloc(2 * pp.m, sizeof(struct apse_ctxt_elem_t));
        for (int i = 0; i < 2 * pp.m; ++i) {
            element_init_G1(ctxts[i].ca, pp.pairing);
            element_init_G1(ctxts[i].cb, pp.pairing);
        }

    }
    _end = get_time();
    fprintf(stderr, "Initialization: %f\n", _end - _start);
    total += _end - _start;

    res = _connect_to_ca(&pp, &mpk, &pk, &sk, attrs);
    if (res == -1) goto cleanup;
    _start = get_time();
    {
        /* XXX: doesn't work yet */
        apse_unlink(&pp, &rpk, &rsk, &pk, &sk);
    }
    _end = get_time();
    fprintf(stderr, "Randomize pk: %f\n", _end - _start);
    total += _end - _start;

    /* Connect to server */
    if ((fd = net_init_client(host, port)) == -1) {
        perror("net_init_client");
        goto cleanup;
    }

    _start = get_time();
    {
        apse_pk_send(&pp, &pk, fd); /* XXX: should be rpk */
    }
    _end = get_time();
    fprintf(stderr, "Send pk: %f\n", _end - _start);
    total += _end - _start;

    _start = get_time();
    {
        for (int i = 0; i < 2 * pp.m; ++i) {
            if (net_recv_element(fd, ctxts[i].ca) == -1)
                goto cleanup;
            if (net_recv_element(fd, ctxts[i].cb) == -1)
                goto cleanup;
        }
        if (gc_comm_recv(fd, &gc) == -1)
            goto cleanup;
    }
    _end = get_time();
    fprintf(stderr, "receive ctxt/gc: %f\n", _end - _start);
    total += _end - _start;

    _start = get_time();
    {
        block *input_labels;
        block output_label, r;

        input_labels = allocate_blocks(pp.m);
        res = _decrypt(&pp, &sk, ctxts, input_labels, attrs, NULL); /* XXX: should be rsk */
        if (res == -1) {
            free(input_labels);
            goto cleanup;
        }
        res = _evaluate(&gc, input_labels, &output_label, NULL);
        if (res == -1) {
            free(input_labels);
            goto cleanup;
        }
        gc_built = 1;
        res = _commit(output_label, &r, fd, NULL);
        if (res == -1) {
            free(input_labels);
            goto cleanup;
        }
        res = _check(&pp, &pk, &gc, ctxts, fd, NULL);
        if (res == -1) {
            free(input_labels);
            goto cleanup;
        }

        net_send(fd, &output_label, sizeof output_label, 0);
        net_send(fd, &r, sizeof r, 0);
    
        free(input_labels);
    }
    _end = get_time();
    total += _end - _start;

    _start = get_time();
    {
        block a, acom, b;
        if (RAND_bytes((unsigned char *) &b, sizeof b) == 0) {
            fprintf(stderr, "RAND_bytes failed\n");
            goto cleanup;
        }
        net_recv(fd, &acom, sizeof acom, 0);
        net_send(fd, &b, sizeof b, 0);
        net_recv(fd, &a, sizeof a, 0);
        if (unequal_blocks(acom, commit(a, zero_block()))) {
            printf("CHEAT: invalid commitment\n");
            goto cleanup;
        }
        key = xorBlocks(a, b);
    }
    _end = get_time();
    fprintf(stderr, "Coin tossing: %f\n", _end - _start);
    total += _end - _start;


    res = 0;

cleanup:
    _start = get_time();
    {
        for (int i = 0; i < 2 * pp.m; ++i) {
            element_clear(ctxts[i].ca);
            element_clear(ctxts[i].cb);
        }
        free(ctxts);

        apse_sk_clear(&pp, &rsk);
        apse_pk_clear(&pp, &rpk);
        apse_sk_clear(&pp, &sk);
        apse_pk_clear(&pp, &pk);
        apse_master_clear(&pp, &mpk);
        apse_pp_clear(&pp);

        if (gc_built)
            removeGarbledCircuit(&gc);

        if (fd != -1)
            close(fd);
    }
    _end = get_time();
    fprintf(stderr, "Cleanup: %f\n", _end - _start);
    total += _end - _start;

    fprintf(stderr, "Total time: %f\n", total);

    printf("KEY: ");
    print_block(key);
    printf("\n");

    return res;
}
