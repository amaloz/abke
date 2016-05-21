#include "bls.h"
#include "util.h"

int
bls_init(struct bls_t *bls)
{
    bn_t ord;

    bls_pk_init(bls);
    bn_new(bls->privkey);
    bn_new(ord);

    g1_get_ord(ord);
    bn_rand_mod(bls->privkey, ord);

    g2_rand(bls->g);
    g2_mul_norm(bls->pubkey, bls->g, bls->privkey);

    bn_free(ord);

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
    g2_new(bls->g);
    g2_new(bls->pubkey);
    g1_new(bls->h);
    g2_get_gen(bls->g);
    g2_get_gen(bls->pubkey);
    g1_get_gen(bls->h);
}

void
bls_pk_clear(struct bls_t *bls)
{
    g2_free(bls->g);
    g1_free(bls->h);
    g2_free(bls->pubkey);
}

size_t
bls_pk_length(struct bls_t *bls)
{
    size_t length = 0;
    length += g2_length_in_bytes_(bls->g);
    length += g1_length_in_bytes_(bls->h);
    length += g2_length_in_bytes_(bls->pubkey);
    return length;
}

size_t
bls_pk_to_bytes(uint8_t *buf, struct bls_t *bls)
{
    size_t p = 0;
    p += g2_to_bytes_(buf + p, bls->g);
    p += g1_to_bytes_(buf + p, bls->h);
    p += g2_to_bytes_(buf + p, bls->pubkey);
    return p;
}

size_t
bls_pk_from_bytes(struct bls_t *bls, uint8_t *buf)
{
    size_t p = 0;
    p += g2_from_bytes_(bls->g, buf + p);
    p += g1_from_bytes_(bls->h, buf + p);
    p += g2_from_bytes_(bls->pubkey, buf + p);
    return p;
}

void
bls_pk_print(struct bls_t *bls)
{
    printf("BLS public key:\n");
    g2_print(bls->g);
    printf("\n");
    g1_print(bls->h);
    printf("\n");
    g2_print(bls->pubkey);
    printf("\n");
}

void
bls_sign(struct bls_t *bls, g1_t out, g1_t in)
{
    g1_mul_norm(out, in, bls->privkey);
}

int
bls_verify(struct bls_t *bls, g1_t sig, g1_t h)
{
    gt_t t1, t2;
    int res;

    gt_new(t1);
    gt_new(t2);
    pc_map(t1, sig, bls->g);
    pc_map(t2, h, bls->pubkey);
    res = gt_cmp(t1, t2);
    gt_free(t1);
    gt_free(t2);
    return res == CMP_EQ;
}
