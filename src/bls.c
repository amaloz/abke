#include "bls.h"

int
bls_init(struct bls_t *bls, pairing_t pairing)
{
    bls_pk_init(bls, pairing);
    element_init_Zr(bls->privkey, pairing);

    element_random(bls->g);
    element_random(bls->privkey);
    element_pow_zn(bls->pubkey, bls->g, bls->privkey);

    return 0;
}

void
bls_clear(struct bls_t *bls)
{
    bls_pk_clear(bls);
    element_clear(bls->privkey);
}

int
bls_pk_init(struct bls_t *bls, pairing_t pairing)
{
    element_init_G2(bls->g, pairing);
    element_init_G2(bls->pubkey, pairing);
    element_init_G1(bls->h, pairing);
    return 0;
}

void
bls_pk_clear(struct bls_t *bls)
{
    element_clear(bls->g);
    element_clear(bls->h);
    element_clear(bls->pubkey);
}

void
bls_sign(struct bls_t *bls, element_t out, element_t in)
{
    element_pow_zn(out, in, bls->privkey);
}

int
bls_verify(struct bls_t *bls, element_t sig, element_t h, pairing_t pairing)
{
    element_t t1, t2;
    int res;

    element_init_GT(t1, pairing);
    element_init_GT(t2, pairing);
    pairing_apply(t1, sig, bls->g, pairing);
    pairing_apply(t2, h, bls->pubkey, pairing);
    res = element_cmp(t1, t2);
    element_clear(t1);
    element_clear(t2);
    return !res;
}
