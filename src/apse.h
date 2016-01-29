#ifndef APSE_H
#define APSE_H

#include "bls.h"
#include "justGarble.h"

struct apse_pp_t {
    int m;
    pairing_t pairing;
};

struct apse_master_t {
    struct bls_t gsig;
    struct bls_t hsig;
    struct bls_t usig;
    struct bls_t *jsigs;
};

struct apse_pk_t {
    element_t g, h, u;
    element_t gsig, hsig, usig;
    element_t *es;
    element_t *esigs;
};

struct apse_sk_t {
    element_t *rs;
};

struct apse_ctxt_t {
    element_t g, h;
    element_t *c2s;
};

void
apse_pp_init(struct apse_pp_t *pp, int m, const char *fname);
void
apse_pp_clear(struct apse_pp_t *pp);

void
apse_master_init(struct apse_pp_t *pp, struct apse_master_t *master);
void
apse_master_clear(const struct apse_pp_t *pp, struct apse_master_t *master);

void
apse_mpk_init(struct apse_pp_t *pp, struct apse_master_t *master);
void
apse_mpk_clear(struct apse_pp_t *pp, struct apse_master_t *master);

void
apse_pk_init(struct apse_pp_t *pp, struct apse_pk_t *pk);
void
apse_pk_clear(const struct apse_pp_t *pp, struct apse_pk_t *pk);

void
apse_sk_init(struct apse_pp_t *pp, struct apse_sk_t *sk);
void
apse_sk_clear(const struct apse_pp_t *pp, struct apse_sk_t *sk);

void
apse_ctxt_init(struct apse_pp_t *pp, struct apse_ctxt_t *ctxt);
void
apse_ctxt_clear(struct apse_pp_t *pp, struct apse_ctxt_t *ctxt);


void
apse_mpk_send(const struct apse_pp_t *pp, struct apse_master_t *master, int fd);
void
apse_mpk_recv(struct apse_pp_t *pp, struct apse_master_t *master, int fd);

int
apse_pk_send(const struct apse_pp_t *pp, struct apse_pk_t *pk, int fd);
int
apse_pk_recv(const struct apse_pp_t *pp, struct apse_pk_t *pk, int fd);

int
apse_sk_send(const struct apse_pp_t *pp, struct apse_sk_t *sk, int fd);
int
apse_sk_recv(const struct apse_pp_t *pp, struct apse_sk_t *sk, int fd);

int
apse_ctxt_send(const struct apse_pp_t *pp, struct apse_ctxt_t *ctxt, int fd);
int
apse_ctxt_recv(const struct apse_pp_t *pp, struct apse_ctxt_t *ctxt, int fd);


void
apse_pp_print(struct apse_pp_t *pp);
void
apse_pk_print(struct apse_pp_t *pp, struct apse_pk_t *pk);
void
apse_sk_print(struct apse_pp_t *pp, struct apse_sk_t *sk);


void
apse_gen(struct apse_pp_t *pp, struct apse_master_t *msk,
         struct apse_pk_t *pk, struct apse_sk_t *sk, const int *attrs);
int
apse_vrfy(struct apse_pp_t *pp, struct apse_master_t *mpk, struct apse_pk_t *pk);
void
apse_enc(struct apse_pp_t *pp, struct apse_pk_t *pk,
         struct apse_ctxt_t *ciphertext, element_t *plaintext,
         const unsigned int *seed);
void
apse_dec(struct apse_pp_t *pp, struct apse_sk_t *sk, element_t *plaintext,
         struct apse_ctxt_t *ciphertext, const int *attrs);
void
apse_unlink(struct apse_pp_t *pp, struct apse_pk_t *rpk, struct apse_sk_t *rsk,
            struct apse_pk_t *pk, struct apse_sk_t *sk);

#endif
