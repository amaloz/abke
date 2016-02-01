#include "apse.h"
#include "ca.h"
#include "gc.h"
#include "gc_comm.h"
#include "net.h"
#include "util.h"

#include <assert.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include "policies.h"

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
         translation_t *translations, const int *attrs, abke_time_t *total)
{
    abke_time_t _start, _end;
    _start = get_time();
    {
        element_t *inputs;
        AES_KEY key;
        block blk;
        translation_t trans;

        inputs = calloc(pp->m, sizeof(element_t));
        for (int i = 0; i < pp->m; ++i) {
            element_init_G1(inputs[i], pp->pairing);
        }
        apse_dec(pp, sk, inputs, ctxt, attrs);
        for (int i = 0; i < pp->m; ++i) {
            blk = element_to_block(inputs[i]);

            AES_set_decrypt_key((unsigned char *) &blk, 128, &key);
            memcpy(&trans, &translations[2 * i], sizeof(translation_t));
            AES_ecb_decrypt_blks(trans.map, 2, &key);

            if (equal_blocks(trans.map[1], zero_block())) {
                input_labels[i] = trans.map[0];
            } else {
                memcpy(&trans, &translations[2 * i + 1], sizeof(translation_t));
                AES_ecb_decrypt_blks(trans.map, 2, &key);

                assert(equal_blocks(trans.map[1], zero_block()));
                input_labels[i] = trans.map[0];
            }
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
_check(struct apse_pp_t *pp, struct apse_pk_t *pk, ExtGarbledCircuit *egc,
       struct apse_ctxt_t *ctxt, const int *attrs, int fd, abke_time_t *comm,
       abke_time_t *comp)
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
    int *flipped_attrs;

    int res = -1;
    abke_time_t _start, _end, _comm = 0.0, _comp = 0.0;

    _start = get_time();
    {
        apse_ctxt_init(pp, &claimed_ctxt);
        claimed_inputs = calloc(2 * pp->m, sizeof(element_t));
        for (int i = 0; i < 2 * pp->m; ++i) {
            element_init_G1(claimed_inputs[i], pp->pairing);
        }
        claimed_input_labels = allocate_blocks(2 * pp->m);
        flipped_attrs = calloc(pp->m, sizeof(int));
        for (int i = 0; i < pp->m; ++i) {
            flipped_attrs[i] = !attrs[i];
        }
    }
    _end = get_time();
    _comp += _end - _start;

    _start = get_time();
    {
        if (net_recv(fd, &length, sizeof length, 0) == -1)
            goto cleanup;
        if ((buf = malloc(length)) == NULL)
            goto cleanup;
        if (net_recv(fd, buf, length, 0) == -1)
            goto cleanup;
    }
    _end = get_time();
    _comm += _end - _start;
    res = -1;

    _start = get_time();
    memcpy(&gc_seed, buf + p, sizeof gc_seed);
    p += sizeof gc_seed;
    memcpy(&enc_seed, buf + p, sizeof enc_seed);
    p += sizeof enc_seed;
    for (int i = 0; i < 2 * pp->m; ++i) {
        p += element_from_bytes_(claimed_inputs[i], buf + p);
    }
    
    for (int i = 0; i < pp->m; ++i) {
        block blk;
        AES_KEY key;
        translation_t trans;

        blk = element_to_block(claimed_inputs[2 * i]);
        AES_set_decrypt_key((unsigned char *) &blk, 128, &key);
        memcpy(&trans, egc->translations[2 * i].map, sizeof(translation_t));
        AES_ecb_decrypt_blks(trans.map, 2, &key);

        if (equal_blocks(trans.map[1], zero_block())) {
            claimed_input_labels[2 * i] = trans.map[0];

            blk = element_to_block(claimed_inputs[2 * i + 1]);
            AES_set_decrypt_key((unsigned char *) &blk, 128, &key);
            memcpy(&trans, egc->translations[2 * i + 1].map, sizeof(translation_t));
            AES_ecb_decrypt_blks(trans.map, 2, &key);
            if (unequal_blocks(trans.map[1], zero_block())) {
                printf("CHEAT: input %d doesn't map to valid wire label\n", i);
                goto cleanup;
            }
            claimed_input_labels[2 * i + 1] = trans.map[0];
        } else {
            memcpy(&trans, egc->translations[2 * i + 1].map, sizeof(translation_t));
            AES_ecb_decrypt_blks(trans.map, 2, &key);
            if (unequal_blocks(trans.map[1], zero_block())) {
                printf("CHEAT: input %d doesn't map to valid wire label\n", i);
                goto cleanup;
            }
            claimed_input_labels[2 * i] = trans.map[0];
            blk = element_to_block(claimed_inputs[2 * i + 1]);
            AES_set_decrypt_key((unsigned char *) &blk, 128, &key);
            memcpy(&trans, egc->translations[2 * i].map, sizeof(translation_t));
            AES_ecb_decrypt_blks(trans.map, 2, &key);
            if (unequal_blocks(trans.map[1], zero_block())) {
                printf("CHEAT: input %d doesn't map to valid wire label\n", i);
                goto cleanup;
            }
            claimed_input_labels[2 * i + 1] = trans.map[0];
        }
    }

    apse_enc_select(pp, pk, flipped_attrs, &claimed_ctxt, claimed_inputs, &enc_seed);
    for (int i = 0; i < pp->m; ++i) {
        if (element_cmp(claimed_ctxt.c2s[2 * i + flipped_attrs[i]],
                        ctxt->c2s[2 * i + flipped_attrs[i]])) {
            printf("CHEAT: input %d doesn't check out\n", i);
            goto cleanup;
        }
    }

    /* Regarble the circuit to verify that it was constructed correctly */
    hashGarbledCircuit(&egc->gc, gc_hash, GARBLE_TYPE_STANDARD);
    (void) seedRandom(&gc_seed);
    build_AND_policy(&gc2, pp->m);
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
    free(flipped_attrs);
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
client_go(const char *host, const char *port, const int *attrs, int m,
          const char *param)
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
    ExtGarbledCircuit egc;
    int gc_built = 0;
    abke_time_t _start, _end, comm = 0.0, comp = 0.0;
    int res = -1;

    fprintf(stderr, "Starting client with m = %d and pairing %s\n", m, param);
    fprintf(stderr, "Attribute vector: ");
    for (int i = 0; i < m; ++i) {
        fprintf(stderr, "%d", attrs[i]);
    }
    fprintf(stderr, "\n\n");

    _start = get_time();
    {
        apse_pp_init(&pp, m, param);
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
        if (apse_pk_send(&pp, &pk, fd) == -1)
            goto cleanup;
    }
    _end = get_time();
    fprintf(stderr, "Send public key: %f\n", _end - _start);
    comm += _end - _start;

    _start = get_time();
    {
        if (apse_ctxt_recv(&pp, &ctxt, fd) == -1)
            goto cleanup;
    }
    _end = get_time();
    fprintf(stderr, "Receive ciphertext: %f\n", _end - _start);
    comm += _end - _start;
    
    _start = get_time();
    {
        if (gc_comm_recv(fd, &egc) == -1)
            goto cleanup;
    }
    _end = get_time();
    fprintf(stderr, "Receive garbled circuit: %f\n", _end - _start);
    comm += _end - _start;

    {
        res = _decrypt(&pp, &sk, &ctxt, input_labels, egc.translations, attrs, &comp);
    }
    if (res == -1) goto cleanup;

    _start = get_time();
    {
        evaluate(&egc.gc, input_labels, &output_label, GARBLE_TYPE_STANDARD);
        gc_built = 1;
    }
    _end = get_time();
    fprintf(stderr, "Evaluate garbled circuit: %f\n", _end - _start);
    comp += _end - _start;

    res = _commit(output_label, &decom, fd, &comm, &comp);
    if (res == -1) goto cleanup;
    res = _check(&pp, &pk, &egc, &ctxt, attrs, fd, &comm, &comp);
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
            removeGarbledCircuit(&egc.gc);
        if (egc.translations)
            free(egc.translations);

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
