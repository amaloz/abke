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

#include <garble/aes.h>
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
         block *ttables, const int *attrs, enum ase_type_e type)
{
    g1_t *inputs;
    AES_KEY key;
    block blk;

    inputs = calloc(pp->m, sizeof(g1_t));
    for (int i = 0; i < pp->m; ++i) {
        g1_new(inputs[i]);
        g1_get_gen(inputs[i]);
    }
    ase_dec(pp, sk, inputs, ctxt, attrs, type);
    for (int i = 0; i < pp->m; ++i) {
        blk = hash(inputs[i], i, attrs[i]);
        AES_set_decrypt_key(blk, &key);
        input_labels[i] = ttables[2 * i + attrs[i]];
        AES_ecb_decrypt_blks(&input_labels[i], 1, &key);
    }
    for (int i = 0; i < pp->m; ++i) {
        g1_free(inputs[i]);
    }
    free(inputs);
    return 0;
}

static int
_commit(block label, block *decom, FILE *f, abke_time_t *comm, abke_time_t *comp)
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
        *comp = _end - _start;

    _start = get_time();
    {
        net_send(f, &commitment, sizeof commitment);
    }
    _end = get_time();
    fprintf(stderr, "Send commitment: %f\n", _end - _start);
    if (comm)
        *comm = _end - _start;
    return 0;
}

static int
_check(struct ase_pp_t *pp, struct ase_pk_t *pk, ExtGarbledCircuit *egc,
       struct ase_ctxt_t *ctxt, const int *attrs, int q, FILE *f,
       abke_time_t *comm, abke_time_t *comp, enum ase_type_e type)
{
    garble_circuit gc2;
    int gc_built = 0;
    unsigned char gc_hash[SHA_DIGEST_LENGTH];
    struct ase_ctxt_t claimed_ctxt;
    g1_t *claimed_inputs;
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
        claimed_inputs = calloc(2 * pp->m, sizeof(g1_t));
        for (int i = 0; i < 2 * pp->m; ++i) {
            g1_new(claimed_inputs[i]);
            g1_get_gen(claimed_inputs[i]);
        }
        claimed_input_labels = garble_allocate_blocks(2 * pp->m);
        flipped_attrs = calloc(pp->m, sizeof(int));
        for (int i = 0; i < pp->m; ++i) {
            flipped_attrs[i] = !attrs[i];
        }
    }
    _end = get_time();
    _comp += _end - _start;
    fprintf(stderr, "Check (init): %f\n", _end - _start);

    _start = get_time();
    {
        net_recv(f, &length, sizeof length);
        if ((buf = malloc(length)) == NULL)
            goto cleanup;
        net_recv(f, buf, length);
        memcpy(&gc_seed, buf + p, sizeof gc_seed);
        p += sizeof gc_seed;
        memcpy(&enc_seed, buf + p, sizeof enc_seed);
        p += sizeof enc_seed;
        for (int i = 0; i < 2 * pp->m; ++i) {
            p += g1_from_bytes_(claimed_inputs[i], buf + p);
        }
    }
    _end = get_time();
    _comm += _end - _start;
    fprintf(stderr, "Check (comm): %f\n", _end - _start);

    _start = get_time();
    res = -1;
    /* Check if claimed inputs decrypt correctly */
    ase_enc(pp, pk, flipped_attrs, &claimed_ctxt, claimed_inputs, &enc_seed, type);
    for (int i = 0; i < pp->m; ++i) {
        switch (type) {
        case ASE_HOMOSIG:
            if (g1_cmp(claimed_ctxt.homosig.c2s[2 * i + flipped_attrs[i]],
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
    _end = get_time();
    _comp += _end - _start;
    fprintf(stderr, "Check (re-encrypt): %f\n", _end - _start);

    _start = get_time();
    /* Check that label map is correct and retrieve claimed input labels */
    for (int i = 0; i < 2 * pp->m; ++i) {
        block blk;
        AES_KEY key;

        blk = hash(claimed_inputs[i], i / 2, i % 2);
        AES_set_decrypt_key(blk, &key);
        AES_ecb_decrypt_blks(&egc->ttables[i], 1, &key);
        claimed_input_labels[i] = egc->ttables[i];
    }

    /* Regarble the circuit to verify that it was constructed correctly */
    garble_hash(&egc->gc, gc_hash);
    build_AND_policy(&gc2, pp->m, q);
    (void) garble_seed(&gc_seed);
    garble_garble(&gc2, claimed_input_labels, NULL);
    gc_built = 1;
    if (garble_check(&gc2, gc_hash) != 0) {
        printf("CHEAT: GCs don't check out\n");
        goto cleanup;
    }
    res = 0;
        
cleanup:
    free(buf);
    for (int i = 0; i < 2 * pp->m; ++i) {
        g1_free(claimed_inputs[i]);
    }
    free(claimed_inputs);
    free(claimed_input_labels);
    free(flipped_attrs);
    ase_ctxt_clear(pp, &claimed_ctxt, type);

    if (gc_built)
        garble_delete(&gc2);

    _end = get_time();
    _comp += _end - _start;

    fprintf(stderr, "Check (re-garble): %f\n", _end - _start);

    if (comm)
        *comm = _comm;
    if (comp)
        *comp = _comp;
    return res;
}

int
client_go(const char *host, const char *port, const int *attrs, int m,
          int q, struct measurement_t *measurements, enum ase_type_e type)
{
    int fd = -1;
    FILE *f = NULL;
    struct ase_pp_t pp;
    struct ase_master_t mpk;
    struct ase_pk_t pk;
    struct ase_sk_t sk;
    struct ase_ctxt_t ctxt;
    block *input_labels;
    block output_label, decom;
    block key = garble_zero_block();
    ExtGarbledCircuit egc;
    int gc_built = 0;
    abke_time_t _start, _end, comm = 0.0, comp = 0.0, ocomp = 0.0;
    abke_time_t tmp_comp, tmp_comm;
    int res = -1;

    fprintf(stderr, "Starting client with m = %d\n", m);
    fprintf(stderr, "Attribute vector: ");
    for (int i = 0; i < m; ++i) {
        fprintf(stderr, "%d", attrs[i]);
    }
    fprintf(stderr, "\n\n");

    _start = get_time();
    {
        ase_pp_init(&pp, m);
        ase_mpk_init(&pp, &mpk, type);
        ase_pk_init(&pp, &pk, type);
        ase_sk_init(&pp, &sk, type);
        ase_ctxt_init(&pp, &ctxt, type);
        input_labels = garble_allocate_blocks(pp.m);
        egc.ttables = NULL;
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
    if ((f = fdopen(fd, "r+")) == NULL) {
        perror("fdopen");
        goto cleanup;
    }

    _start = get_time();
    {
        if (ase_pk_send(&pp, &pk, f, type) == -1)
            goto cleanup;
    }
    _end = get_time();
    fprintf(stderr, "Send public key: %f\n", _end - _start);
    comm += _end - _start;

    _start = get_time();
    {
        if (ase_ctxt_recv(&pp, &ctxt, f, type) == -1)
            goto cleanup;
    }
    _end = get_time();
    fprintf(stderr, "Receive ciphertext: %f\n", _end - _start);
    comm += _end - _start;
    
    _start = get_time();
    {
        if (gc_comm_recv(f, &egc) == -1)
            goto cleanup;
    }
    _end = get_time();
    fprintf(stderr, "Receive garbled circuit: %f\n", _end - _start);
    comm += _end - _start;

    _start = get_time();
    {
        res = _decrypt(&pp, &sk, &ctxt, input_labels, egc.ttables, attrs, type);
        if (res == -1) goto cleanup;
    }
    _end = get_time();
    fprintf(stderr, "Decrypt: %f\n", _end - _start);
    comp += _end - _start;
    ocomp += _end - _start;

    _start = get_time();
    {
        garble_eval(&egc.gc, input_labels, &output_label, NULL);
        gc_built = 1;
    }
    _end = get_time();
    fprintf(stderr, "Evaluate garbled circuit: %f\n", _end - _start);
    comp += _end - _start;
    ocomp += _end - _start;

    res = _commit(output_label, &decom, f, &tmp_comm, &tmp_comp);
    if (res == -1) goto cleanup;
    comm += tmp_comm;
    comp += tmp_comp;
    ocomp += tmp_comp;

    res = _check(&pp, &pk, &egc, &ctxt, attrs, q, f, &tmp_comm, &tmp_comp, type);
    if (res == -1) goto cleanup;
    comm += tmp_comm;
    comp += tmp_comp;
    ocomp += tmp_comp;

    _start = get_time();
    {
        net_send(f, &output_label, sizeof output_label);
        net_send(f, &decom, sizeof decom);
    }
    _end = get_time();
    fprintf(stderr, "Send decommitment: %f\n", _end - _start);
    comm += _end - _start;

    _start = get_time();
    {
        block a, acom, b = garble_zero_block();
        if (RAND_bytes((unsigned char *) &b, sizeof b) == 0) {
            fprintf(stderr, "RAND_bytes failed\n");
            goto cleanup;
        }
        net_recv(f, &acom, sizeof acom);
        net_send(f, &b, sizeof b);
        net_recv(f, &a, sizeof a);
        if (garble_unequal(acom, commit(a, garble_zero_block()))) {
            printf("CHEAT: invalid commitment\n");
            goto cleanup;
        }
        key = garble_xor(a, b);
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
            garble_delete(&egc.gc);
        if (egc.ttables)
            free(egc.ttables);

        if (f)
            fclose(f);
        if (fd != -1)
            close(fd);
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
