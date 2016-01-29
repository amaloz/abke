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
         struct apse_ctxt_t *ctxt, block *input_labels,
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
        apse_dec(pp, sk, inputs, ctxt, attrs);
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
_commit(block label, block *r, int fd, abke_time_t *comm, abke_time_t *comp)
{
    block commitment;
    abke_time_t _start, _end;

    _start = get_time();
    if (RAND_bytes((unsigned char *) r, sizeof(block)) == 0) {
        fprintf(stderr, "RAND_bytes failed\n");
        return -1;
    }
    commitment = commit(label, *r);
    _end = get_time();
    fprintf(stderr, "Compute commitment: %f\n", _end - _start);
    if (comp)
        *comp += _end - _start;

    _start = get_time();
    net_send(fd, &commitment, sizeof commitment, 0);
    _end = get_time();
    fprintf(stderr, "Send commitment: %f\n", _end - _start);
    if (comm)
        *comm += _end - _start;
    return 0;
}

static int
_check(struct apse_pp_t *pp, struct apse_pk_t *pk, GarbledCircuit *gc,
       struct apse_ctxt_t *ctxt, int fd, abke_time_t *comm, abke_time_t *comp)
{
    GarbledCircuit gc2;
    int gc_built = 0;
    unsigned char gc_hash[SHA_DIGEST_LENGTH];
    struct apse_ctxt_t claimed_ctxt;
    element_t *claimed_inputs;
    block *claimed_input_labels;
    block gc_seed;
    unsigned int enc_seed;
    size_t length, p = 0;
    unsigned char *buf = NULL;

    int res = -1;
    abke_time_t _start, _end, _comm = 0.0, _comp = 0.0;

    _start = get_time();
    apse_ctxt_init(pp, &claimed_ctxt);
    claimed_inputs = calloc(2 * pp->m, sizeof(element_t));
    for (int i = 0; i < 2 * pp->m; ++i) {
        element_init_G1(claimed_inputs[i], pp->pairing);
    }
    claimed_input_labels = allocate_blocks(2 * pp->m);
    _end = get_time();
    _comp += _end - _start;

    _start = get_time();
    if ((res = net_recv(fd, &length, sizeof length, 0)) == -1)
        goto cleanup;
    if ((buf = malloc(length)) == NULL)
        goto cleanup;
    if ((res = net_recv(fd, buf, length, 0)) == -1)
        goto cleanup;
    _end = get_time();
    _comm += _end - _start;

    _start = get_time();
    memcpy(&gc_seed, buf + p, sizeof gc_seed);
    p += sizeof gc_seed;
    memcpy(&enc_seed, buf + p, sizeof enc_seed);
    p += sizeof enc_seed;
    for (int i = 0; i < 2 * pp->m; ++i) {
        p += element_from_bytes_compressed(claimed_inputs[i], buf + p);
        claimed_input_labels[i] = element_to_block(claimed_inputs[i]);
    }

    apse_enc(pp, pk, &claimed_ctxt, claimed_inputs, &enc_seed);
    for (int i = 0; i < pp->m; ++i) {
        if (element_cmp(claimed_ctxt.c2s[2 * i], ctxt->c2s[2 * i])
            || element_cmp(claimed_ctxt.c2s[2 * i + 1], ctxt->c2s[2 * i + 1])) {
            printf("CHEAT: input %d doesn't check out\n", i);
            goto cleanup;
        }
    }

    /* Regarble the circuit to verify that it was constructed correctly */
    hashGarbledCircuit(gc, gc_hash, GARBLE_TYPE_STANDARD);
    (void) seedRandom(&gc_seed);
    build_AND_circuit(&gc2, pp->m);
    garbleCircuit(&gc2, claimed_input_labels, NULL, GARBLE_TYPE_STANDARD);
    gc_built = 1;
    if (checkGarbledCircuit(&gc2, gc_hash, GARBLE_TYPE_STANDARD) != 0) {
        printf("CHEAT: GCs don't check out\n");
        goto cleanup;
    }
    res = 0;
        
cleanup:
    for (int i = 0; i < 2 * pp->m; ++i) {
        element_clear(claimed_inputs[i]);
    }
    free(claimed_inputs);
    free(claimed_input_labels);
    apse_ctxt_clear(pp, &claimed_ctxt);

    if (gc_built)
        removeGarbledCircuit(&gc2);

    _end = get_time();
    _comp += _end - _start;

    fprintf(stderr, "Check: %f\n", _comm + _comp);
    if (comm)
        *comm += _comm;
    if (comp)
        *comp += _comp;
    return res;
}

int
client_go(const char *host, const char *port, const int *attrs, int m)
{
    int fd = -1;
    struct apse_pp_t pp;
    struct apse_master_t mpk;
    struct apse_pk_t pk;
    struct apse_sk_t sk;
    struct apse_ctxt_t ctxt;
    block *input_labels;
    block output_label, decom;
    block key = zero_block();
    GarbledCircuit gc;
    int gc_built = 0;
    abke_time_t _start, _end, comm = 0.0, comp = 0.0;
    int res = -1;

    fprintf(stderr, "Starting client with m = %d\n", m);

    _start = get_time();
    {
        apse_pp_init(&pp, m, PARAMFILE);
        apse_mpk_init(&pp, &mpk);
        apse_pk_init(&pp, &pk);
        apse_sk_init(&pp, &sk);
        apse_ctxt_init(&pp, &ctxt);
        input_labels = allocate_blocks(pp.m);

    }
    _end = get_time();
    fprintf(stderr, "Initialize: %f\n", _end - _start);
    comp += _end - _start;

    res = _connect_to_ca(&pp, &mpk, &pk, &sk, attrs);
    if (res == -1) goto cleanup;

    _start = get_time();
    {
        apse_unlink(&pp, &pk, &sk, &pk, &sk);
    }
    _end = get_time();
    fprintf(stderr, "Randomize public key: %f\n", _end - _start);
    comp += _end - _start;

    /* Connect to server */
    if ((fd = net_init_client(host, port)) == -1) {
        perror("net_init_client");
        goto cleanup;
    }

    _start = get_time();
    {
        apse_pk_send(&pp, &pk, fd);
    }
    _end = get_time();
    fprintf(stderr, "Send public key: %f\n", _end - _start);
    comm += _end - _start;

    _start = get_time();
    {
        apse_ctxt_recv(&pp, &ctxt, fd);
    }
    _end = get_time();
    fprintf(stderr, "Receive ciphertext: %f\n", _end - _start);
    comm += _end - _start;
    
    _start = get_time();
    {
        gc_comm_recv(fd, &gc);
    }
    _end = get_time();
    fprintf(stderr, "Receive garbled circuit: %f\n", _end - _start);
    comm += _end - _start;

    res = _decrypt(&pp, &sk, &ctxt, input_labels, attrs, &comp);
    if (res == -1) goto cleanup;

    _start = get_time();
    {
        evaluate(&gc, input_labels, &output_label, GARBLE_TYPE_STANDARD);
        gc_built = 1;
    }
    _end = get_time();
    fprintf(stderr, "Evaluate garbled circuit: %f\n", _end - _start);
    comp += _end - _start;

    res = _commit(output_label, &decom, fd, &comm, &comp);
    if (res == -1) goto cleanup;
    res = _check(&pp, &pk, &gc, &ctxt, fd, &comm, &comp);
    if (res == -1) goto cleanup;

    _start = get_time();
    {
        net_send(fd, &output_label, sizeof output_label, 0);
        net_send(fd, &decom, sizeof decom, 0);
    }
    _end = get_time();
    fprintf(stderr, "Send decommitment: %f\n", _end - _start);
    comm += _end - _start;

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
    comm += _end - _start;

    res = 0;
cleanup:
    _start = get_time();
    {
        apse_ctxt_clear(&pp, &ctxt);
        apse_mpk_clear(&pp, &mpk);
        apse_sk_clear(&pp, &sk);
        apse_pk_clear(&pp, &pk);
        apse_pp_clear(&pp);

        if (gc_built)
            removeGarbledCircuit(&gc);

        if (fd != -1)
            close(fd);
    }
    _end = get_time();
    fprintf(stderr, "Cleanup: %f\n", _end - _start);
    comp += _end - _start;

    fprintf(stderr, "\n");
    fprintf(stderr, "Communication: %f\n", comm);
    fprintf(stderr, "Computation: %f\n", comp);
    fprintf(stderr, "Total time: %f\n", comm + comp);

    printf("\nKEY: ");
    print_block(key);
    printf("\n");

    return res;
}
