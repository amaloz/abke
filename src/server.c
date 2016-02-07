#include "party.h"

#include "gc.h"
#include "gc_comm.h"
#include "net.h"
#include "util.h"

/* #define THPOOL 1 */

#ifdef THPOOL
#include "thpool.h"
#endif

#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <openssl/rand.h>

#include "policies.h"

#ifdef THPOOL
struct thpool_args_t {
    struct ase_pp_t *pp;
    struct ase_master_t *mpk;
    struct ase_pk_t *pk;
    int result;
};

static threadpool g_thpool;
static struct thpool_args_t g_thpool_args;

static void *
thpool_ase_vrfy(void *vargs)
{
    struct thpool_args_t *args = (struct thpool_args_t *) vargs;

    args->result = ase_vrfy(args->pp, args->mpk, args->pk);

    return NULL;
}
#endif  /* THPOOL */

static int
_connect_to_ca(struct ase_pp_t *pp, struct ase_master_t *mpk,
               enum ase_type_e type)
{
    abke_time_t _start, _end;
    _start = get_time();
    {
        if (ca_info(pp, mpk, ROLE_SERVER, NULL, NULL, NULL, type) == -1) {
            fprintf(stderr, "Unable to connect to CA\n");
            return -1;
        }
    }
    _end = get_time();
    fprintf(stderr, "Get CA info: %f\n", _end - _start);
    return 0;
}

static int
_get_pk(struct ase_pp_t *pp, struct ase_master_t *mpk, struct ase_pk_t *pk,
        int fd, abke_time_t *comm, abke_time_t *comp, enum ase_type_e type)
{
    abke_time_t _start, _end;

    _start = get_time();
    ase_pk_recv(pp, pk, fd, type);
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
    thpool_add_work(g_thpool, thpool_ase_vrfy, &g_thpool_args);
#else
    if (!ase_vrfy(pp, mpk, pk, type)) {
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
_encrypt(struct ase_pp_t *pp, struct ase_pk_t *pk,
         struct ase_ctxt_t *ctxt, element_t *inputs,
         unsigned int *seed, abke_time_t *total, enum ase_type_e type)
{
    abke_time_t _start, _end;
    _start = get_time();
    {
        if (RAND_bytes((unsigned char *) seed, sizeof(unsigned int)) == 0) {
            fprintf(stderr, "RAND_bytes failed\n");
            return -1;
        }
        ase_enc(pp, pk, ctxt, inputs, seed, type);
#ifdef THPOOL
        thpool_wait(g_thpool);
        if (g_thpool_args.result != 1) {
            fprintf(stderr, "CHEAT: public key failed to verify\n");
            return -1;
        }
#endif
    }
    _end = get_time();
    fprintf(stderr, "Encrypt: %f\n", _end - _start);
    if (total)
        *total += _end - _start;
    return 0;
}

static int
_send_randomness_and_inputs(const struct ase_pp_t *pp, block gc_seed,
                            unsigned int enc_seed, element_t *inputs,
                            int fd, abke_time_t *total)
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
            length += element_length_in_bytes_(inputs[i]);
        }
        if (net_send(fd, &length, sizeof length, 0) == -1)
            return -1;
        if ((buf = malloc(length)) == NULL)
            return -1;
        memcpy(buf + p, &gc_seed, sizeof gc_seed);
        p += sizeof gc_seed;
        memcpy(buf + p, &enc_seed, sizeof enc_seed);
        p += sizeof enc_seed;
        for (int i = 0; i < 2 * pp->m; ++i) {
            p += element_to_bytes_(buf + p, inputs[i]);
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
server_go(const char *host, const char *port, int m, int q,
          const char *param, struct measurement_t *measurements,
          enum ase_type_e type)
{
    int sockfd = -1, fd = -1;
    block gc_seed, commitment;
    struct ase_pp_t pp;
    struct ase_master_t mpk;
    struct ase_pk_t client_pk;
    struct ase_ctxt_t ctxt;
    ExtGarbledCircuit egc;
    int gc_built = 0;
    element_t *inputs;
    block *input_labels, output_labels[2];
    block key = zero_block();
    unsigned int enc_seed;
    abke_time_t _start, _end, comm = 0.0, comp = 0.0;
    int res = -1;

    fprintf(stderr, "Starting server with m = %d and pairing %s\n", m, param);
#ifdef THPOOL
    fprintf(stderr, "Using thread pool\n");
#endif
    fprintf(stderr, "\n");

    _start = get_time();
    {
        block seed;
#ifdef THPOOL
        g_thpool = thpool_init(2); /* XXX: hardcoded value */
#endif
        ase_pp_init(&pp, m, param);
        ase_mpk_init(&pp, &mpk, type);
        ase_pk_init(&pp, &client_pk, type);
        ase_ctxt_init(&pp, &ctxt, type);
        inputs = calloc(2 * pp.m, sizeof(element_t));
        for (int i = 0; i < 2 * pp.m; ++i) {
            element_init_G1(inputs[i], pp.pairing);
        }
        egc.map = calloc(2 * pp.m, sizeof(label_map_t));
        input_labels = allocate_blocks(2 * pp.m);
        /* Need to call seedRandom for createInputLabels() */
        (void) RAND_bytes((unsigned char *) &seed, sizeof seed);
        (void) seedRandom(&seed);
        createInputLabels(input_labels, pp.m);
    }
    _end = get_time();
    fprintf(stderr, "Initialize: %f\n", _end - _start);
    comp += _end - _start;

    _start = get_time();
    {
        AES_KEY key;
        block *map;
        block blk;
        unsigned char *rand;

        rand = calloc((pp.m + 8) / 8, sizeof(char));
        RAND_bytes(rand, (pp.m + 8) / 8);
        for (int i = 0; i < pp.m; ++i) {
            bool choice = rand[(i / 8)] & (1 << (i % 8)) ? true : false;
            element_random(inputs[2 * i]);
            element_random(inputs[2 * i + 1]);

            blk = element_to_block(inputs[2 * i + (choice ? 1 : 0)]);
            map = egc.map[2 * i].map;
            map[0] = input_labels[2 * i + (choice ? 1 : 0)];
            map[1] = zero_block();

            AES_set_encrypt_key(blk, &key);
            AES_ecb_encrypt_blks(map, 2, &key);

            blk = element_to_block(inputs[2 * i + (choice ? 0 : 1)]);
            map = egc.map[2 * i + 1].map;
            map[0] = input_labels[2 * i + (choice ? 0 : 1)];
            map[1] = zero_block();

            AES_set_encrypt_key(blk, &key);
            AES_ecb_encrypt_blks(map, 2, &key);
        }
        free(rand);
    }
    _end = get_time();
    fprintf(stderr, "Generate random inputs and label map: %f\n", _end - _start);
    comp += _end - _start;

    /* Need to re-seed before garbling so that when re-garbling we'll be in the
     * same state as now */
    (void) RAND_bytes((unsigned char *) &gc_seed, sizeof gc_seed);
    (void) seedRandom(&gc_seed);
        _start = get_time();
    {
        build_AND_policy(&egc.gc, pp.m, q);
        (void) garbleCircuit(&egc.gc, input_labels, output_labels, GARBLE_TYPE);
    }
    _end = get_time();
    fprintf(stderr, "Garble circuit: %f\n", _end - _start);
    comp += _end - _start;
    gc_built = 1;

    res = _connect_to_ca(&pp, &mpk, type);
    if (res == -1) goto cleanup;

    /* Reset number of bytes sent/received after connection to CA */
    g_bytes_sent = g_bytes_rcvd = 0;

    /* Initialize server and accept connection from client */
    if ((sockfd = net_init_server(host, port)) == -1) {
        perror("net_init_server");
        exit(EXIT_FAILURE);
    }
    if ((fd = net_server_accept(sockfd)) == -1) {
        perror("net_server_accept");
        exit(EXIT_FAILURE);
    }

    res = _get_pk(&pp, &mpk, &client_pk, fd, &comm, &comp, type);
    if (res == -1) goto cleanup;
    (void) RAND_bytes((unsigned char *) &enc_seed, sizeof enc_seed);
    res = _encrypt(&pp, &client_pk, &ctxt, inputs, &enc_seed, &comp, type);
    if (res == -1) goto cleanup;

    _start = get_time();
    {
        if (ase_ctxt_send(&pp, &ctxt, fd, type) == -1)
            goto cleanup;
    }
    _end = get_time();
    fprintf(stderr, "Send ciphertext: %f\n", _end - _start);
    comm += _end - _start;

    _start = get_time();
    {
        if (gc_comm_send(fd, &egc) == -1)
            goto cleanup;
    }
    _end = get_time();
    fprintf(stderr, "Send garbled circuit: %f\n", _end - _start);
    comm += _end - _start;

    _start = get_time();
    {
        if (net_recv(fd, &commitment, sizeof commitment, 0) == -1)
            goto cleanup;
    }
    _end = get_time();
    fprintf(stderr, "Receive commitment: %f\n", _end - _start);
    comm += _end - _start;

    /* Send randomness and inputs to client */
    res = _send_randomness_and_inputs(&pp, gc_seed, enc_seed, inputs, fd,
                                      &comm);
    if (res == -1) goto cleanup;

    {
        block output_label, r;

        _start = get_time();
        {
            net_recv(fd, &output_label, sizeof output_label, 0);
            net_recv(fd, &r, sizeof r, 0);
        }
        _end = get_time();
        fprintf(stderr, "Receive decommitment: %f\n", _end - _start);
        comm += _end - _start;

        _start = get_time();
        {
            block tmp = commit(output_label, r);
            if (unequal_blocks(commitment, tmp)) {
                printf("CHEAT: commitments not equal\n");
                goto cleanup;
            }
            if (unequal_blocks(output_label, output_labels[1])) {
                printf("CHEAT: not 1-bit output label\n");
                goto cleanup;
            }
        }
        _end = get_time();
        fprintf(stderr, "Check commitment and output label: %f\n", _end - _start);
        comp += _end - _start;
    }

    /* Do coin tossing */
    {
        block a, acom, b;

        _start = get_time();
        {
            if (RAND_bytes((unsigned char *) &a, sizeof a) == 0) {
                fprintf(stderr, "RAND_bytes failed\n");
                goto cleanup;
            }
            acom = commit(a, zero_block());
        }
        _end = get_time();
        fprintf(stderr, "Compute commitment for coin tossing: %f\n", _end - _start);
        comp += _end - _start;

        _start = get_time();
        {
            net_send(fd, &acom, sizeof acom, 0);
            net_recv(fd, &b, sizeof b, 0);
            net_send(fd, &a, sizeof a, 0);
            key = xorBlocks(a, b);
        }
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

        ase_ctxt_clear(&pp, &ctxt, type);
        ase_pk_clear(&pp, &client_pk, type);
        ase_mpk_clear(&pp, &mpk, type);
        ase_pp_clear(&pp);

        if (gc_built)
            removeGarbledCircuit(&egc.gc);
        free(egc.map);

        if (fd != -1)
            close(fd);
        if (sockfd != -1)
            close(sockfd);
    }
    _end = get_time();
    fprintf(stderr, "Cleanup: %f\n", _end - _start);
    comp += _end - _start;

    fprintf(stderr, "\n");
    fprintf(stderr, "Computation:   %f\n", comp);
    fprintf(stderr, "Communication: %f\n", comm);
    fprintf(stderr, "  Bytes sent:     %d\n", g_bytes_sent);
    fprintf(stderr, "  Bytes received: %d\n", g_bytes_rcvd);

    fprintf(stderr, "Total time:    %f\n", comm + comp);

    measurements->comp = comp;
    measurements->comm = comm;
    measurements->bytes_sent = g_bytes_sent;
    measurements->bytes_rcvd = g_bytes_rcvd;

    fprintf(stderr, "\nKEY: ");
    print_block(stderr, key);
    fprintf(stderr, "\n");

    return res;
}
