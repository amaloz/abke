#ifndef BLS_H
#define BLS_H

#include <pbc/pbc.h>

struct bls_t {
    element_t g, h;
    element_t pubkey, privkey;
};

int
bls_init(struct bls_t *bls, pairing_t pairing);
void
bls_clear(struct bls_t *bls);
int
bls_pk_init(struct bls_t *bls, pairing_t pairing);
void
bls_pk_clear(struct bls_t *bls);
void
bls_sign(struct bls_t *bls, element_t out, element_t in);
int
bls_verify(struct bls_t *bls, element_t sig, element_t h, pairing_t pairing);

#endif
