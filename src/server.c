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
#include <garble/aes.h>
#include <garble/block.h>

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
        FILE *f, abke_time_t *comm, abke_time_t *comp, enum ase_type_e type)
{
    abke_time_t _start, _end;

    _start = get_time();
    {
        ase_pk_recv(pp, pk, f, type);
    }
    _end = get_time();
    fprintf(stderr, "Receive public key: %f\n", _end - _start);
    if (comm)
        *comm = _end - _start;

    _start = get_time();
    {
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
    }
    _end = get_time();
    fprintf(stderr, "Verify public key: %f\n", _end - _start);
    if (comp)
        *comp = _end - _start;
    return 0;
}

static int
_encrypt(struct ase_pp_t *pp, struct ase_pk_t *pk,
         struct ase_ctxt_t *ctxt, g1_t *inputs,
         unsigned int *seed, enum ase_type_e type)
{
    if (RAND_bytes((unsigned char *) seed, sizeof(unsigned int)) == 0) {
        fprintf(stderr, "RAND_bytes failed\n");
        return -1;
    }
    ase_enc(pp, pk, NULL, ctxt, inputs, seed, type);
#ifdef THPOOL
    thpool_wait(g_thpool);
    if (g_thpool_args.result != 1) {
        fprintf(stderr, "CHEAT: public key failed to verify\n");
        return -1;
    }
#endif
    return 0;
}

static int
_send_randomness_and_inputs(const struct ase_pp_t *pp, block gc_seed,
                            unsigned int enc_seed, g1_t *inputs,
                            FILE *f, abke_time_t *total)
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
            length += g1_length_in_bytes_(inputs[i]);
        }
        net_send(f, &length, sizeof length);
        if ((buf = malloc(length)) == NULL)
            return -1;
        memcpy(buf + p, &gc_seed, sizeof gc_seed);
        p += sizeof gc_seed;
        memcpy(buf + p, &enc_seed, sizeof enc_seed);
        p += sizeof enc_seed;
        for (int i = 0; i < 2 * pp->m; ++i) {
            p += g1_to_bytes_(buf + p, inputs[i]);
        }
        net_send(f, buf, length);
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
    FILE *f = NULL;
    int sockfd = -1, fd = -1;
    block gc_seed, commitment;
    struct ase_pp_t pp;
    struct ase_master_t mpk;
    struct ase_pk_t client_pk;
    struct ase_ctxt_t ctxt;
    ExtGarbledCircuit egc;
    int gc_built = 0;
    g1_t *inputs;
    block *input_labels, output_labels[2];
    block key = garble_zero_block();
    unsigned int enc_seed;
    abke_time_t _start, _end, comm = 0.0, comp = 0.0, ocomp = 0.0;
    abke_time_t tmp_comp, tmp_comm;
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
        ase_master_init(&pp, &mpk, type);
        ase_pk_init(&pp, &client_pk, type);
        ase_ctxt_init(&pp, &ctxt, type);
        inputs = calloc(2 * pp.m, sizeof(g1_t));
        for (int i = 0; i < 2 * pp.m; ++i) {
            g1_new(inputs[i]);
            g1_get_gen(inputs[i]);
        }
        egc.ttables = calloc(2 * pp.m, sizeof(block));
        input_labels = garble_allocate_blocks(2 * pp.m);
        /* Need to call garble_seed() for garble_create_input_labels() */
        (void) RAND_bytes((unsigned char *) &seed, sizeof seed);
        (void) garble_seed(&seed);
        garble_create_input_labels(input_labels, pp.m, NULL,
                                   GARBLE_TYPE == GARBLE_TYPE_PRIVACY_FREE);
        (void) RAND_bytes((unsigned char *) &enc_seed, sizeof enc_seed);
    }
    _end = get_time();
    fprintf(stderr, "Initialize: %f\n", _end - _start);
    comp += _end - _start;

    _start = get_time();
    for (int i = 0; i < 2 * pp.m; ++i) {
        AES_KEY aeskey;
        block blk;

        blk = hash(inputs[i], i / 2, i % 2);
        AES_set_encrypt_key(blk, &aeskey);
        egc.ttables[i] = input_labels[i];
        AES_ecb_encrypt_blks(&egc.ttables[i], 1, &aeskey);
    }
    _end = get_time();
    fprintf(stderr, "Generate random inputs and translation table: %f\n",
            _end - _start);
    comp += _end - _start;

    /* Need to re-seed before garbling so that when re-garbling we'll be in the
     * same state as now */
    (void) RAND_bytes((unsigned char *) &gc_seed, sizeof gc_seed);
    (void) garble_seed(&gc_seed);
    _start = get_time();
    {
        /* XXX: right now we're hardcoding the policy here */
        build_AND_policy(&egc.gc, pp.m, q);
        (void) garble_garble(&egc.gc, input_labels, output_labels);
        gc_built = 1;
    }
    _end = get_time();
    fprintf(stderr, "Garble circuit: %f\n", _end - _start);
    comp += _end - _start;

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
    if ((f = fdopen(fd, "r+")) == NULL) {
        perror("fdopen");
        exit(EXIT_FAILURE);
    }

    /* ase_pk_recv(&pp, &client_pk, f, type); */
    res = _get_pk(&pp, &mpk, &client_pk, f, &tmp_comm, &tmp_comp, type);
    struct ase_sk_t client_sk;
    int *attrs;
    attrs = calloc(pp.m, sizeof(int));
    for (int i = 0; i < pp.m; ++i)
        attrs[i] = 1;
    ase_sk_init(&pp, &client_sk, type);
    if (res == -1) goto cleanup;
    comm += tmp_comm;
    comp += tmp_comp;
    /* divide by four to mimic 5-user batching of pk verification */
    ocomp = tmp_comp / 4;

    _start = get_time();
    {
        res = _encrypt(&pp, &client_pk, &ctxt, inputs, &enc_seed, type);
        if (res == -1) goto cleanup;
    }
    _end = get_time();
    fprintf(stderr, "Encrypt: %f\n", _end - _start);
    comp += _end - _start;
    ocomp += _end - _start;

    _start = get_time();
    {
        if (ase_ctxt_send(&pp, &ctxt, f, type) == -1)
            goto cleanup;
    }
    _end = get_time();
    fprintf(stderr, "Send ciphertext: %f\n", _end - _start);
    comm += _end - _start;

    _start = get_time();
    {
        if (gc_comm_send(f, &egc) == -1)
            goto cleanup;
    }
    _end = get_time();
    fprintf(stderr, "Send garbled circuit: %f\n", _end - _start);
    comm += _end - _start;

    _start = get_time();
    {
        net_recv(f, &commitment, sizeof commitment);
    }
    _end = get_time();
    fprintf(stderr, "Receive commitment: %f\n", _end - _start);
    comm += _end - _start;

    res = _send_randomness_and_inputs(&pp, gc_seed, enc_seed, inputs, f, &comm);
    if (res == -1) goto cleanup;

    {
        block output_label, r;

        _start = get_time();
        {
            net_recv(f, &output_label, sizeof output_label);
            net_recv(f, &r, sizeof r);
        }
        _end = get_time();
        fprintf(stderr, "Receive decommitment: %f\n", _end - _start);
        comm += _end - _start;

        _start = get_time();
        {
            block tmp = commit(output_label, r);
            if (garble_unequal(commitment, tmp)) {
                printf("CHEAT: commitments not equal\n");
                goto cleanup;
            }
            if (garble_unequal(output_label, output_labels[1])) {
                printf("CHEAT: not 1-bit output label\n");
                goto cleanup;
            }
        }
        _end = get_time();
        fprintf(stderr, "Check commitment and output label: %f\n", _end - _start);
        comp += _end - _start;
        ocomp += _end - _start;
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
            acom = commit(a, garble_zero_block());
        }
        _end = get_time();
        fprintf(stderr, "Compute commitment for coin tossing: %f\n", _end - _start);
        comp += _end - _start;
        ocomp += _end - _start;

        _start = get_time();
        {
            net_send(f, &acom, sizeof acom);
            net_recv(f, &b, sizeof b);
            net_send(f, &a, sizeof a);
            key = garble_xor(a, b);
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
            g1_free(inputs[i]);
        }
        free(inputs);
        free(input_labels);

        ase_ctxt_clear(&pp, &ctxt, type);
        ase_pk_clear(&pp, &client_pk, type);
        ase_master_clear(&pp, &mpk, type);
        ase_pp_clear(&pp);

        if (gc_built)
            garble_delete(&egc.gc);
        free(egc.ttables);

        if (f)
            fclose(f);
        if (fd != -1)
            close(fd);
        if (sockfd != -1)
            close(sockfd);
    }
    _end = get_time();
    fprintf(stderr, "Cleanup: %f\n", _end - _start);
    comp += _end - _start;
    ocomp += _end - _start;

    fprintf(stderr, "\n");
    fprintf(stderr, "Computation:          %f\n", comp);
    fprintf(stderr, "Computation (online): %f\n", ocomp);
    fprintf(stderr, "Communication:        %f\n", comm);
    fprintf(stderr, "  Bytes sent:     %d\n", g_bytes_sent);
    fprintf(stderr, "  Bytes received: %d\n", g_bytes_rcvd);

    fprintf(stderr, "Total time:          %f\n", comm + comp);
    fprintf(stderr, "Total time (online): %f\n", comm + ocomp);

    measurements->comp = comp;
    measurements->ocomp = ocomp;
    measurements->comm = comm;
    measurements->bytes_sent = g_bytes_sent;
    measurements->bytes_rcvd = g_bytes_rcvd;

    block_fprintf(stderr, "\nKEY: %B\n", key);

    return res;
}
