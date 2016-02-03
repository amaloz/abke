#ifndef ABKE_ASE_H
#define ABKE_ASE_H

#include "bls.h"
#include "justGarble.h"

enum ase_type_e { ASE_HOMOSIG, ASE_BONFRA, ASE_NONE };

struct ase_pp_t {
    int m;
    pairing_t pairing;
};

struct ase_master_t {
    struct bls_t gsig;
    struct bls_t hsig;
    struct bls_t usig;
    struct bls_t *jsigs;
};

struct ase_pk_t {
    element_t g, h, u;
    element_t gsig, hsig, usig;
    element_t *es;
    element_t *esigs;
};

struct ase_sk_t {
    element_t *rs;
};

struct ase_ctxt_t {
    element_t g, h;
    element_t *c2s;
};

int
ase_pp_init(struct ase_pp_t *pp, int m, const char *fname);
void
ase_pp_clear(struct ase_pp_t *pp);

void
ase_master_init(struct ase_pp_t *pp, struct ase_master_t *master);
void
ase_master_clear(const struct ase_pp_t *pp, struct ase_master_t *master);

void
ase_mpk_init(struct ase_pp_t *pp, struct ase_master_t *master);
void
ase_mpk_clear(struct ase_pp_t *pp, struct ase_master_t *master);

void
ase_pk_init(struct ase_pp_t *pp, struct ase_pk_t *pk);
void
ase_pk_clear(const struct ase_pp_t *pp, struct ase_pk_t *pk);

void
ase_sk_init(struct ase_pp_t *pp, struct ase_sk_t *sk);
void
ase_sk_clear(const struct ase_pp_t *pp, struct ase_sk_t *sk);

void
ase_ctxt_init(struct ase_pp_t *pp, struct ase_ctxt_t *ctxt);
void
ase_ctxt_clear(struct ase_pp_t *pp, struct ase_ctxt_t *ctxt);


int
ase_mpk_send(const struct ase_pp_t *pp, struct ase_master_t *master, int fd);
int
ase_mpk_recv(struct ase_pp_t *pp, struct ase_master_t *master, int fd);

int
ase_pk_send(const struct ase_pp_t *pp, struct ase_pk_t *pk, int fd);
int
ase_pk_recv(const struct ase_pp_t *pp, struct ase_pk_t *pk, int fd);

int
ase_sk_send(const struct ase_pp_t *pp, struct ase_sk_t *sk, int fd);
int
ase_sk_recv(const struct ase_pp_t *pp, struct ase_sk_t *sk, int fd);

int
ase_ctxt_send(const struct ase_pp_t *pp, struct ase_ctxt_t *ctxt, int fd);
int
ase_ctxt_recv(const struct ase_pp_t *pp, struct ase_ctxt_t *ctxt, int fd);


void
ase_pp_print(struct ase_pp_t *pp);
void
ase_pk_print(struct ase_pp_t *pp, struct ase_pk_t *pk);
void
ase_sk_print(struct ase_pp_t *pp, struct ase_sk_t *sk);


void
ase_gen(struct ase_pp_t *pp, struct ase_master_t *msk,
         struct ase_pk_t *pk, struct ase_sk_t *sk, const int *attrs);
int
ase_vrfy(struct ase_pp_t *pp, struct ase_master_t *mpk, struct ase_pk_t *pk);
void
ase_enc(struct ase_pp_t *pp, struct ase_pk_t *pk,
         struct ase_ctxt_t *ciphertext, element_t *plaintext,
         const unsigned int *seed);
void
ase_enc_select(struct ase_pp_t *pp, struct ase_pk_t *pk, const int *attrs,
                struct ase_ctxt_t *ciphertext, element_t *plaintext,
                const unsigned int *seed);
void
ase_dec(struct ase_pp_t *pp, struct ase_sk_t *sk, element_t *plaintext,
         struct ase_ctxt_t *ciphertext, const int *attrs);
void
ase_unlink(struct ase_pp_t *pp, struct ase_pk_t *rpk, struct ase_sk_t *rsk,
            struct ase_pk_t *pk, struct ase_sk_t *sk);

#endif
