#include "bls.h"
#include "util.h"

int
bls_init(struct bls_t *bls)
{
    bn_t ord;
    g2_t h;

    bls_pk_init(bls);
    bn_new(bls->privkey);
    bn_new(ord);
    g2_new(h);

    g1_get_ord(ord);
    bn_rand_mod(bls->privkey, ord);
    g2_get_gen(h);
    g2_mul_norm(bls->pubkey, h, bls->privkey);

    bn_free(ord);
    g2_free(h);

    return 0;
}

void
bls_clear(struct bls_t *bls)
{
    bls_pk_clear(bls);
    bn_free(bls->privkey);
}

void
bls_pk_init(struct bls_t *bls)
{
    g2_new(bls->pubkey);
    g2_get_gen(bls->pubkey);
}

void
bls_pk_clear(struct bls_t *bls)
{
    g2_free(bls->pubkey);
}

size_t
bls_pk_length(struct bls_t *bls)
{
    return g2_length_in_bytes_(bls->pubkey);
}

size_t
bls_pk_to_bytes(uint8_t *buf, struct bls_t *bls)
{
    return g2_to_bytes_(buf, bls->pubkey);
}

size_t
bls_pk_from_bytes(struct bls_t *bls, uint8_t *buf)
{
    return g2_from_bytes_(bls->pubkey, buf);
}

void
bls_pk_print(struct bls_t *bls)
{
    printf("BLS public key:\n");
    g2_print(bls->pubkey);
    printf("\n");
}

void
bls_sign(struct bls_t *bls, g1_t out, g1_t in)
{
    g1_mul_norm(out, in, bls->privkey);
}

int
bls_verify(struct bls_t *bls, g1_t sig, g1_t msg)
{
    g2_t h;
    gt_t t1, t2;
    int res;

    g2_new(h);
    gt_new(t1);
    gt_new(t2);

    g2_get_gen(h);
    pc_map(t1, sig, h);
    pc_map(t2, msg, bls->pubkey);
    res = gt_cmp(t1, t2);

    g2_free(h);
    gt_free(t1);
    gt_free(t2);
    return res == CMP_EQ;
}

int
bls_batch_verify(struct bls_t *bls, int n, g1_t *sigs, g1_t *msgs)
{
    gt_t t1, t2;
    bn_t exp;
    g1_t tmp_1, acc1, acc2;
    g2_t h;
    int res;

    gt_new(t1);
    gt_new(t2);
    g1_new(tmp_1);
    g1_new(acc1);
    g1_new(acc2);
    bn_new(exp);
    g2_new(h);
    g2_get_gen(h);

    bn_rand(exp, BN_POS, 128);
    g1_mul(acc1, msgs[0], exp);
    g1_mul(acc2, sigs[0], exp);

    for (int i = 1; i < n; ++i) {
        bn_rand(exp, BN_POS, 128);
        g1_mul(tmp_1, msgs[i], exp);
        g1_add(acc1, acc1, tmp_1);

        g1_mul(tmp_1, sigs[i], exp);
        g1_add(acc2, acc2, tmp_1);
    }

    pc_map(t1, acc1, bls->pubkey);
    pc_map(t2, acc2, h);
    res = gt_cmp(t1, t2);

    gt_free(t1);
    gt_free(t2);
    g1_free(tmp_1);
    g1_free(acc1);
    g1_free(acc2);
    bn_free(exp);
    g2_free(h);

    return res == CMP_EQ;
}
