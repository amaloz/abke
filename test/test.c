#include "bls.h"
#include "ase.h"
#include "ase_homosig.h"

static int
check_bls(void)
{
    g1_t in, sig;
    struct bls_t bls;

    bls_init(&bls);
    g1_new(in);
    g1_new(sig);

    g1_rand(in);
    bls_sign(&bls, sig, in);
    if (bls_verify(&bls, sig, in) != 1) {
        printf("verify failed!\n");
        return 1;
    }
    g1_rand(in);
    if (bls_verify(&bls, sig, in) != 0) {
        printf("verify failed!\n");
        return 1;
    }

    g1_rand(in);
    BENCH_BEGIN("bls_sign") {
        BENCH_ADD(bls_sign(&bls, sig, in));
    }
    BENCH_END;
    BENCH_BEGIN("bls_verify") {
        BENCH_ADD(bls_verify(&bls, sig, in));
    }
    BENCH_END;

    bls_clear(&bls);
    g1_free(in);
    g1_free(sig);

    return 0;
}

#define N_BATCH 10

static int
check_bls_batch_verify(void)
{
    struct bls_t bls;
    g1_t *ins;
    g1_t *sigs;

    bls_init(&bls);
    sigs = calloc(N_BATCH, sizeof(g1_t));
    ins =  calloc(N_BATCH, sizeof(g1_t));
    for (int i = 0; i < N_BATCH; ++i) {
        g1_new(ins[i]);
        g1_new(sigs[i]);
        g1_rand(ins[i]);
        bls_sign(&bls, sigs[i], ins[i]);
        if (bls_verify(&bls, sigs[i], ins[i]) != 1) {
            printf("verify failed!\n");
            return 1;
        }
    }

    if (bls_batch_verify(&bls, N_BATCH, sigs, ins) != 1) {
        printf("batch verify failed!\n");
        return 1;
    }

    BENCH_BEGIN("bls_batch_verify") {
        BENCH_ADD(bls_batch_verify(&bls, N_BATCH, sigs, ins));
    }
    BENCH_END;

    return 0;
}

#define N_ATTRS 100

static int
check_ase_homosig(void)
{
    struct ase_pp_t pp;
    struct ase_homosig_master_t master;
    struct ase_homosig_pk_t pk;
    struct ase_homosig_sk_t sk;
    struct ase_homosig_ctxt_t ctxt;
    int *attrs;
    g1_t *plaintext;
    g1_t *output;

    attrs = calloc(N_ATTRS, sizeof(int));
    for (int i = 0; i < N_ATTRS; ++i)
        attrs[i] = 1;

    plaintext = calloc(2 * N_ATTRS, sizeof(g1_t));
    for (int i = 0; i < 2 * N_ATTRS; ++i) {
        g1_new(plaintext[i]);
        g1_rand(plaintext[i]);
    }

    output = calloc(N_ATTRS, sizeof(g1_t));
    for (int i = 0; i < N_ATTRS; ++i) {
        g1_new(output[i]);
        g1_rand(output[i]);
    }

    ase_pp_init(&pp, N_ATTRS);
    ase_homosig_master_init(&pp, &master);
    ase_homosig_pk_init(&pp, &pk);
    ase_homosig_sk_init(&pp, &sk);
    ase_homosig_ctxt_init(&pp, &ctxt);

    ase_homosig_gen(&pp, &master, &pk, &sk, attrs);
    if (ase_homosig_vrfy(&pp, &master, &pk) != 1) {
        printf("Verification failed!\n");
        return 1;
    }
    ase_homosig_enc(&pp, &pk, NULL, &ctxt, plaintext, NULL);
    ase_homosig_dec(&pp, &sk, output, &ctxt, attrs);

    for (int i = 0; i < N_ATTRS; ++i) {
        if (g1_cmp(plaintext[2 * i + 1], output[i]) != CMP_EQ) {
            printf("Encryption failed!\n");
            return 1;
        }
    }

    for (int i = 0; i < N_ATTRS; ++i) {
        g1_free(plaintext[i]);
    }
    free(plaintext);

    ase_homosig_master_clear(&pp, &master);
    ase_homosig_pk_clear(&pp, &pk);
    ase_homosig_sk_clear(&pp, &sk);
    ase_homosig_ctxt_clear(&pp, &ctxt);
    ase_pp_clear(&pp);

    return 0;
}

int
main(void)
{
    if (core_init() != STS_OK) {
        core_clean();
        return EXIT_FAILURE;
    }

    if (pc_param_set_any() != STS_OK) {
        core_clean();
        return EXIT_FAILURE;
    }

    pc_param_print();

    if (check_bls())
        return 1;
    if (check_bls_batch_verify())
        return 1;
    if (check_ase_homosig())
        return 1;

    return 0;
}
