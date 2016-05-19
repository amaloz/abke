#ifndef ASE_ASE_HOMOSIG_H
#define ASE_ASE_HOMOSIG_H

#include "ase.h"

void
ase_homosig_master_init(struct ase_pp_t *pp,
                        struct ase_homosig_master_t *master);
void
ase_homosig_master_clear(const struct ase_pp_t *pp,
                         struct ase_homosig_master_t *master);
void
ase_homosig_mpk_init(struct ase_pp_t *pp, struct ase_homosig_master_t *master);
void
ase_homosig_mpk_clear(struct ase_pp_t *pp, struct ase_homosig_master_t *master);
void
ase_homosig_pk_init(struct ase_pp_t *pp, struct ase_homosig_pk_t *pk);
void
ase_homosig_pk_clear(const struct ase_pp_t *pp, struct ase_homosig_pk_t *pk);
void
ase_homosig_sk_init(struct ase_pp_t *pp, struct ase_homosig_sk_t *sk);
void
ase_homosig_sk_clear(const struct ase_pp_t *pp, struct ase_homosig_sk_t *sk);
void
ase_homosig_ctxt_init(struct ase_pp_t *pp, struct ase_homosig_ctxt_t *ctxt);
void
ase_homosig_ctxt_clear(struct ase_pp_t *pp, struct ase_homosig_ctxt_t *ctxt);

void
ase_homosig_mpk_print(const struct ase_pp_t *pp, struct ase_homosig_master_t *master);
void
ase_homosig_pk_print(const struct ase_pp_t *pp, struct ase_homosig_pk_t *pk);
void
ase_homosig_sk_print(const struct ase_pp_t *pp, struct ase_homosig_sk_t *sk);
void
ase_homosig_ctxt_print(const struct ase_pp_t *pp, struct ase_homosig_ctxt_t *ctxt);

int
ase_homosig_mpk_send(const struct ase_pp_t *pp,
                     struct ase_homosig_master_t *master, FILE *f);
int 
ase_homosig_mpk_recv(struct ase_pp_t *pp, struct ase_homosig_master_t *master,
                     FILE *f);
int
ase_homosig_pk_send(const struct ase_pp_t *pp, struct ase_homosig_pk_t *pk,
                    FILE *f);
int
ase_homosig_pk_recv(const struct ase_pp_t *pp, struct ase_homosig_pk_t *pk,
                    FILE *f);
int
ase_homosig_sk_send(const struct ase_pp_t *pp, struct ase_homosig_sk_t *sk,
                    FILE *f);
int
ase_homosig_sk_recv(const struct ase_pp_t *pp, struct ase_homosig_sk_t *sk,
                    FILE *f);
int
ase_homosig_ctxt_send(const struct ase_pp_t *pp, struct ase_homosig_ctxt_t *ctxt,
                      FILE *f);
int
ase_homosig_ctxt_recv(const struct ase_pp_t *pp, struct ase_homosig_ctxt_t *ctxt,
                      FILE *f);

void
ase_homosig_gen(struct ase_pp_t *pp, struct ase_homosig_master_t *msk,
                struct ase_homosig_pk_t *pk, struct ase_homosig_sk_t *sk,
                const int *attrs);
int
ase_homosig_vrfy(struct ase_pp_t *pp, struct ase_homosig_master_t *mpk,
                 struct ase_homosig_pk_t *pk);
void
ase_homosig_enc(struct ase_pp_t *pp, struct ase_homosig_pk_t *pk,
                const int *attrs, struct ase_homosig_ctxt_t *ciphertext,
                g1_t *plaintext, const unsigned int *seed);
void
ase_homosig_dec(struct ase_pp_t *pp, struct ase_homosig_sk_t *sk,
                g1_t *plaintext, struct ase_homosig_ctxt_t *ciphertext,
                const int *attrs);
void
ase_homosig_unlink(struct ase_pp_t *pp, struct ase_homosig_pk_t *rpk,
                   struct ase_homosig_sk_t *rsk, struct ase_homosig_pk_t *pk,
                   struct ase_homosig_sk_t *sk);

#endif
