#include "party.h"

#include "gc.h"
#include "gc_comm.h"
#include "net.h"
#include "util.h"

#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include "policies.h"

static int
_connect_to_ca(struct ase_pp_t *pp, struct ase_master_t *mpk,
               struct ase_pk_t *pk, struct ase_sk_t *sk, const int *attrs,
               enum ase_type_e type)
{
    abke_time_t _start, _end;
    _start = get_time();
    {
        if (ca_info(pp, mpk, ROLE_CLIENT, pk, sk, attrs, type) == -1) {
            fprintf(stderr, "ERROR: Unable to connect to CA\n");
            return -1;
        }
    }
    _end = get_time();
    fprintf(stderr, "Get CA info: %f\n", _end - _start);
    return 0;
}

static int
_decrypt(struct ase_pp_t *pp, struct ase_sk_t *sk,
         struct ase_ctxt_t *ctxt, block *input_labels,
         label_map_t *map, const int *attrs, abke_time_t *total,
         enum ase_type_e type)
{
    abke_time_t _start, _end;
    _start = get_time();
    {
        element_t *inputs;
        AES_KEY key;
        block blk;
        label_map_t tmp;

        inputs = calloc(pp->m, sizeof(element_t));
        for (int i = 0; i < pp->m; ++i) {
            element_init_G1(inputs[i], pp->pairing);
        }
        ase_dec(pp, sk, inputs, ctxt, attrs, type);
        for (int i = 0; i < pp->m; ++i) {
            blk = element_to_block(inputs[i]);

            AES_set_decrypt_key(blk, &key);
            memcpy(&tmp, &map[2 * i], sizeof(label_map_t));
            AES_ecb_decrypt_blks(tmp.map, 2, &key);

            if (equal_blocks(tmp.map[1], zero_block())) {
                input_labels[i] = tmp.map[0];
            } else {
                memcpy(&tmp, &map[2 * i + 1], sizeof(label_map_t));
                AES_ecb_decrypt_blks(tmp.map, 2, &key);
                /* If blocks unequal can't check here as that leads to selective
                 * failure attack */
                input_labels[i] = tmp.map[0];
            }

        }
        for (int i = 0; i < pp->m; ++i) {
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
_commit(block label, block *decom, int fd, abke_time_t *comm, abke_time_t *comp)
{
    block commitment;
    abke_time_t _start, _end;

    _start = get_time();
    {
        if (RAND_bytes((unsigned char *) decom, sizeof(block)) == 0) {
            fprintf(stderr, "RAND_bytes failed\n");
            return -1;
        }
        commitment = commit(label, *decom);
    }
    _end = get_time();
    fprintf(stderr, "Compute commitment: %f\n", _end - _start);
    if (comp)
        *comp += _end - _start;

    _start = get_time();
    {
        net_send(fd, &commitment, sizeof commitment, 0);
    }
    _end = get_time();
    fprintf(stderr, "Send commitment: %f\n", _end - _start);
    if (comm)
        *comm += _end - _start;
    return 0;
}

static int
_check(struct ase_pp_t *pp, struct ase_pk_t *pk, ExtGarbledCircuit *egc,
       struct ase_ctxt_t *ctxt, const int *attrs, int q, int fd,
       abke_time_t *comm, abke_time_t *comp, enum ase_type_e type)
{
    GarbledCircuit gc2;
    int gc_built = 0;
    unsigned char gc_hash[SHA_DIGEST_LENGTH];
    struct ase_ctxt_t claimed_ctxt;
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
        ase_ctxt_init(pp, &claimed_ctxt, type);
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
        memcpy(&gc_seed, buf + p, sizeof gc_seed);
        p += sizeof gc_seed;
        memcpy(&enc_seed, buf + p, sizeof enc_seed);
        p += sizeof enc_seed;
        for (int i = 0; i < 2 * pp->m; ++i) {
            p += element_from_bytes_(claimed_inputs[i], buf + p);
        }
    }
    _end = get_time();
    _comm += _end - _start;

    _start = get_time();
    res = -1;

    /* Check if claimed inputs decrypt correctly */
    ase_enc_select(pp, pk, flipped_attrs, &claimed_ctxt, claimed_inputs,
                   &enc_seed, type);
    for (int i = 0; i < pp->m; ++i) {
        switch (type) {
        case ASE_HOMOSIG:
            if (element_cmp(claimed_ctxt.homosig.c2s[2 * i + flipped_attrs[i]],
                            ctxt->homosig.c2s[2 * i + flipped_attrs[i]])) {
                printf("CHEAT: input %d doesn't check out\n", i);
                goto cleanup;
            }
            break;
        default:
            assert(0);
            abort();
        }
    }

    /* Check that label map is correct and retrieve claimed input labels */
    for (int i = 0; i < pp->m; ++i) {
        block blk;
        AES_KEY key;
        label_map_t map;

        blk = element_to_block(claimed_inputs[2 * i]);
        AES_set_decrypt_key(blk, &key);
        memcpy(&map, egc->map[2 * i].map, sizeof(label_map_t));
        AES_ecb_decrypt_blks(map.map, 2, &key);

        if (equal_blocks(map.map[1], zero_block())) {
            claimed_input_labels[2 * i] = map.map[0];

            blk = element_to_block(claimed_inputs[2 * i + 1]);
            AES_set_decrypt_key(blk, &key);
            memcpy(&map, egc->map[2 * i + 1].map, sizeof(label_map_t));
            AES_ecb_decrypt_blks(map.map, 2, &key);
            if (unequal_blocks(map.map[1], zero_block())) {
                printf("CHEAT: input %d doesn't map to valid wire label\n", i);
                goto cleanup;
            }
            claimed_input_labels[2 * i + 1] = map.map[0];
        } else {
            memcpy(&map, egc->map[2 * i + 1].map, sizeof(label_map_t));
            AES_ecb_decrypt_blks(map.map, 2, &key);
            if (unequal_blocks(map.map[1], zero_block())) {
                printf("CHEAT: input %d doesn't map to valid wire label\n", i);
                goto cleanup;
            }
            claimed_input_labels[2 * i] = map.map[0];
            blk = element_to_block(claimed_inputs[2 * i + 1]);
            AES_set_decrypt_key(blk, &key);
            memcpy(&map, egc->map[2 * i].map, sizeof(label_map_t));
            AES_ecb_decrypt_blks(map.map, 2, &key);
            if (unequal_blocks(map.map[1], zero_block())) {
                printf("CHEAT: input %d doesn't map to valid wire label\n", i);
                goto cleanup;
            }
            claimed_input_labels[2 * i + 1] = map.map[0];
        }
    }

    /* Regarble the circuit to verify that it was constructed correctly */
    hashGarbledCircuit(&egc->gc, gc_hash, GARBLE_TYPE);
    build_AND_policy(&gc2, pp->m, q);
    (void) seedRandom(&gc_seed);
    garbleCircuit(&gc2, claimed_input_labels, NULL, GARBLE_TYPE);
    gc_built = 1;
    if (checkGarbledCircuit(&gc2, gc_hash, GARBLE_TYPE) != 0) {
        printf("CHEAT: GCs don't check out\n");
        goto cleanup;
    }
    res = 0;
        
cleanup:
    free(buf);
    for (int i = 0; i < 2 * pp->m; ++i) {
        element_clear(claimed_inputs[i]);
    }
    free(claimed_inputs);
    free(claimed_input_labels);
    free(flipped_attrs);
    ase_ctxt_clear(pp, &claimed_ctxt, type);

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
          int q, const char *param, struct measurement_t *measurements,
          enum ase_type_e type)
{
    int fd = -1;
    struct ase_pp_t pp;
    struct ase_master_t mpk;
    struct ase_pk_t pk;
    struct ase_sk_t sk;
    struct ase_ctxt_t ctxt;
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
        ase_pp_init(&pp, m, param);
        ase_mpk_init(&pp, &mpk, type);
        ase_pk_init(&pp, &pk, type);
        ase_sk_init(&pp, &sk, type);
        ase_ctxt_init(&pp, &ctxt, type);
        input_labels = allocate_blocks(pp.m);
        egc.map = NULL;
    }
    _end = get_time();
    fprintf(stderr, "Initialize: %f\n", _end - _start);
    comp += _end - _start;

    res = _connect_to_ca(&pp, &mpk, &pk, &sk, attrs, type);
    if (res == -1) goto cleanup;

    /* Reset number of bytes sent/received after connection to CA */
    g_bytes_sent = g_bytes_rcvd = 0;

    _start = get_time();
    {
        ase_unlink(&pp, &pk, &sk, &pk, &sk, type);
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
        if (ase_pk_send(&pp, &pk, fd, type) == -1)
            goto cleanup;
    }
    _end = get_time();
    fprintf(stderr, "Send public key: %f\n", _end - _start);
    comm += _end - _start;

    _start = get_time();
    {
        if (ase_ctxt_recv(&pp, &ctxt, fd, type) == -1)
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
        res = _decrypt(&pp, &sk, &ctxt, input_labels, egc.map, attrs, &comp,
                       type);
    }
    if (res == -1) goto cleanup;

    _start = get_time();
    {
        evaluate(&egc.gc, input_labels, &output_label, GARBLE_TYPE);
        gc_built = 1;
    }
    _end = get_time();
    fprintf(stderr, "Evaluate garbled circuit: %f\n", _end - _start);
    comp += _end - _start;

    res = _commit(output_label, &decom, fd, &comm, &comp);
    if (res == -1) goto cleanup;
    res = _check(&pp, &pk, &egc, &ctxt, attrs, q, fd, &comm, &comp, type);
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
        block a, acom, b = zero_block();
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
        free(input_labels);
        ase_ctxt_clear(&pp, &ctxt, type);
        ase_mpk_clear(&pp, &mpk, type);
        ase_sk_clear(&pp, &sk, type);
        ase_pk_clear(&pp, &pk, type);
        ase_pp_clear(&pp);

        if (gc_built)
            removeGarbledCircuit(&egc.gc);
        if (egc.map)
            free(egc.map);

        if (fd != -1)
            close(fd);
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
