#ifndef BLS_H
#define BLS_H

#include <relic/relic.h>

struct bls_t {
    g1_t h;
    g2_t g, pubkey;
    /* element_t g, h; */
    bn_t privkey;
    /* element_t pubkey, privkey; */
};

int
bls_init(struct bls_t *bls);
void
bls_clear(struct bls_t *bls);
void
bls_pk_init(struct bls_t *bls);
void
bls_pk_clear(struct bls_t *bls);
size_t
bls_pk_length(struct bls_t *bls);
size_t
bls_pk_to_bytes(uint8_t *buf, struct bls_t *bls);
size_t
bls_pk_from_bytes(struct bls_t *bls, uint8_t *buf);
void
bls_pk_print(struct bls_t *bls);
void
bls_sign(struct bls_t *bls, g1_t out, g1_t in);
int
bls_verify(struct bls_t *bls, g1_t sig, g1_t h);

#endif
