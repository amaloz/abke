#include "apse.h"
#include "ca.h"
#include "gc_comm.h"
#include "net.h"
#include "util.h"

/* #define THPOOL 1 */

#ifdef THPOOL
#include "thpool.h"
#endif

#include <assert.h>
#include <unistd.h>
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
_connect_to_ca(struct apse_pp_t *pp, struct apse_master_t *mpk)
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
_garble(const struct apse_pp_t *pp, GarbledCircuit *gc, block *input_labels,
        block *output_labels, abke_time_t *total)
{
    abke_time_t _start, _end;
    _start = get_time();
    {
        build_AND_circuit(gc, pp->m);
        garbleCircuit(gc, input_labels, output_labels, GARBLE_TYPE_STANDARD);
    }
    _end = get_time();
    fprintf(stderr, "Garble circuit: %f\n", _end - _start);
    if (total)
        *total += _end - _start;
    return 0;
}

struct thpool_args_t {
    struct apse_pp_t *pp;
    struct apse_master_t *mpk;
    struct apse_pk_t *pk;
    int result;
};

#ifdef THPOOL
static threadpool g_thpool;
static struct thpool_args_t g_thpool_args;

static void *
thpool_apse_vrfy(void *vargs)
{
    struct thpool_args_t *args = (struct thpool_args_t *) vargs;

    args->result = apse_vrfy(args->pp, args->mpk, args->pk);

    return NULL;
}
#endif

static int
_get_pk(struct apse_pp_t *pp, struct apse_master_t *mpk, struct apse_pk_t *pk,
        int fd, abke_time_t *comm, abke_time_t *comp)
{
    abke_time_t _start, _end;

    _start = get_time();
    apse_pk_recv(pp, pk, fd);
    _end = get_time();
    fprintf(stderr, "Receive public key: %f\n", _end - _start);
    if (comm)
        *comm += _end - _start;

    _start = get_time();
#ifdef THPOOL
    g_thpool_args.pp = pp;
    g_thpool_args.mpk = mpk;
    g_thpool_args.pk = pk;
    g_thpool_args.result = 0;
    thpool_add_work(g_thpool, thpool_apse_vrfy, &g_thpool_args);
#else
    if (!apse_vrfy(pp, mpk, pk)) {
        fprintf(stderr, "pk fails to verify\n");
        return -1;
    }
#endif
    _end = get_time();
    fprintf(stderr, "Verify public key: %f\n", _end - _start);
    if (comp)
        *comp += _end - _start;
    return 0;
}

static int
_encrypt(struct apse_pp_t *pp, struct apse_pk_t *pk,
         struct apse_ctxt_t *ctxt, element_t *inputs,
         unsigned int *seed, abke_time_t *total)
{
    abke_time_t _start, _end;
    _start = get_time();
    {
        if (RAND_bytes((unsigned char *) seed, sizeof(unsigned int)) == 0) {
            fprintf(stderr, "RAND_bytes failed\n");
            return -1;
        }
        apse_enc(pp, pk, ctxt, inputs, seed);
    }
    _end = get_time();
    fprintf(stderr, "Encrypt: %f\n", _end - _start);
    if (total)
        *total += _end - _start;
    return 0;
}

static int
_send_randomness_and_inputs(const struct apse_pp_t *pp, block gc_seed,
                            unsigned int enc_seed, element_t *inputs, int fd,
                            abke_time_t *total)
{
    int res = 0;
    abke_time_t _start, _end;
    _start = get_time();
    {
        size_t length = 0, p = 0;
        unsigned char *buf;

        length += sizeof gc_seed;
        length += sizeof enc_seed;
        for (int i = 0; i < 2 * pp->m; ++i) {
            length += element_length_in_bytes_compressed(inputs[i]);
        }
        if ((res = net_send(fd, &length, sizeof length, 0)) == -1)
            return -1;
        if ((buf = malloc(length)) == NULL)
            return -1;
        memcpy(buf + p, &gc_seed, sizeof gc_seed);
        p += sizeof gc_seed;
        memcpy(buf + p, &enc_seed, sizeof enc_seed);
        p += sizeof enc_seed;
        for (int i = 0; i < 2 * pp->m; ++i) {
            p += element_to_bytes_compressed(buf + p, inputs[i]);
        }
        res = net_send(fd, buf, length, 0);
        free(buf);
    }
    _end = get_time();
    fprintf(stderr, "Send randomness and inputs: %f\n", _end - _start);
    if (total)
        *total += _end - _start;
    return res;
}


int
server_go(const char *host, const char *port, int m)
{
    int sockfd = -1, fd = -1;
    block gc_seed, commitment;
    struct apse_pp_t pp;
    struct apse_master_t mpk;
    struct apse_pk_t client_pk;
    struct apse_ctxt_t ctxt;
    GarbledCircuit gc;
    int gc_built = 0;
    element_t *inputs;
    block *input_labels, output_labels[2], key = zero_block();
    unsigned int enc_seed;
    abke_time_t _start, _end, comm = 0.0, comp = 0.0;
    int res = -1;

    fprintf(stderr, "Starting server with m = %d\n", m);
#ifdef THPOOL
    fprintf(stderr, "Using thread pool\n");
#endif
    fprintf(stderr, "\n");
    

    /* Initialization */
    _start = get_time();
    {
#ifdef THPOOL
        g_thpool = thpool_init(2); /* XXX: hardcoded value */
#endif
        gc_seed = seedRandom(NULL);
        apse_pp_init(&pp, m, PARAMFILE);
        apse_mpk_init(&pp, &mpk);
        apse_pk_init(&pp, &client_pk);
        apse_ctxt_init(&pp, &ctxt);
        inputs = calloc(2 * pp.m, sizeof(element_t));
        for (int i = 0; i < 2 * pp.m; ++i) {
            element_init_G1(inputs[i], pp.pairing);
        }
        input_labels = allocate_blocks(2 * pp.m);
    }
    _end = get_time();
    fprintf(stderr, "Initialize: %f\n", _end - _start);
    comp += _end - _start;

    _start = get_time();
    {
        for (int i = 0; i < 2 * pp.m; ++i) {
            element_random(inputs[i]);
            input_labels[i] = element_to_block(inputs[i]);
        }
    }
    _end = get_time();
    fprintf(stderr, "Generate random inputs: %f\n", _end - _start);
    comp += _end - _start;

    res = _connect_to_ca(&pp, &mpk);
    if (res == -1) goto cleanup;
    res = _garble(&pp, &gc, input_labels, output_labels, &comp);
    if (res == -1) goto cleanup;
    gc_built = 1;

    /* Initialize server and accept connection from client */
    if ((sockfd = net_init_server(host, port)) == -1) {
        perror("net_init_server");
        exit(EXIT_FAILURE);
    }
    if ((fd = net_server_accept(sockfd)) == -1) {
        perror("net_server_accept");
        exit(EXIT_FAILURE);
    }

    res = _get_pk(&pp, &mpk, &client_pk, fd, &comm, &comp);
    if (res == -1) goto cleanup;
    res = _encrypt(&pp, &client_pk, &ctxt, inputs, &enc_seed, &comp);
    if (res == -1) goto cleanup;
#ifdef THPOOL
    thpool_wait(g_thpool);
    if (g_thpool_args.result != 1) {
        fprintf(stderr, "CHEAT: public key failed to veify\n");
        goto cleanup;
    }
#endif

    _start = get_time();
    {
        apse_ctxt_send(&pp, &ctxt, fd);
    }
    _end = get_time();
    fprintf(stderr, "Send ciphertext: %f\n", _end - _start);
    comm += _end - _start;

    _start = get_time();
    {
        gc_comm_send(fd, &gc);
    }
    _end = get_time();
    fprintf(stderr, "Send garbled circuit: %f\n", _end - _start);
    comm += _end - _start;

    _start = get_time();
    {
        net_recv(fd, &commitment, sizeof commitment, 0);
    }
    _end = get_time();
    fprintf(stderr, "Receive commitment: %f\n", _end - _start);
    comm += _end - _start;

    /* Send randomness and inputs to client */
    res = _send_randomness_and_inputs(&pp, gc_seed, enc_seed, inputs, fd, &comm);
    if (res == -1) goto cleanup;


    {
        block output_label, r, commitment2;

        _start = get_time();
        net_recv(fd, &output_label, sizeof output_label, 0);
        net_recv(fd, &r, sizeof r, 0);
        _end = get_time();
        fprintf(stderr, "Receive decommitment: %f\n", _end - _start);
        comm += _end - _start;

        _start = get_time();
        commitment2 = commit(output_label, r);
        if (unequal_blocks(commitment, commitment2)) {
            printf("CHEAT: commitments not equal\n");
            goto cleanup;
        }
        if (unequal_blocks(output_label, output_labels[1])) {
            printf("CHEAT: not 1-bit output label\n");
            goto cleanup;
        }
        _end = get_time();
        fprintf(stderr, "Check commitment and output label: %f\n", _end - _start);
        comp += _end - _start;
    }

    {
        block a, acom, b;

        _start = get_time();
        if (RAND_bytes((unsigned char *) &a, sizeof a) == 0) {
            fprintf(stderr, "RAND_bytes failed\n");
            goto cleanup;
        }
        acom = commit(a, zero_block());
        _end = get_time();
        fprintf(stderr, "Compute commitment for coin tossing: %f\n", _end - _start);
        comp += _end - _start;

        _start = get_time();
        net_send(fd, &acom, sizeof acom, 0);
        net_recv(fd, &b, sizeof b, 0);
        net_send(fd, &a, sizeof a, 0);
        key = xorBlocks(a, b);
        _end = get_time();
        fprintf(stderr, "Coin tossing: %f\n", _end - _start);
        comm += _end - _start;

    }

    res = 0;

cleanup:
    _start = get_time();
    {
#ifdef THPOOL
        thpool_destroy(g_thpool);
#endif
        for (int i = 0; i < 2 * m; ++i) {
            element_clear(inputs[i]);
        }
        free(inputs);
        free(input_labels);

        apse_ctxt_clear(&pp, &ctxt);
        apse_pk_clear(&pp, &client_pk);
        apse_mpk_clear(&pp, &mpk);
        apse_pp_clear(&pp);

        if (gc_built)
            removeGarbledCircuit(&gc);

        if (fd != -1)
            close(fd);
        if (sockfd != -1)
            close(sockfd);
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
