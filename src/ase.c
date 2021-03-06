#include "ase.h"
#include "ase_homosig.h"
#include "net.h"
#include "util.h"

#include <assert.h>

int
ase_pp_init(struct ase_pp_t *pp, int m)
{
    pp->m = m;
    return 0;
}

void
ase_pp_clear(struct ase_pp_t *pp)
{
}

void
ase_master_init(struct ase_pp_t *pp, struct ase_master_t *master,
                enum ase_type_e type)
{
    switch (type) {
    case ASE_HOMOSIG:
        ase_homosig_master_init(pp, &master->homosig);
        break;
    default:
        assert(0);
        abort();
    }
}

void
ase_master_clear(const struct ase_pp_t *pp, struct ase_master_t *master,
                 enum ase_type_e type)
{
    switch (type) {
    case ASE_HOMOSIG:
        ase_homosig_master_clear(pp, &master->homosig);
        break;
    default:
        assert(0);
        abort();
    }
}

void
ase_mpk_init(struct ase_pp_t *pp, struct ase_master_t *master,
             enum ase_type_e type)
{
    switch (type) {
    case ASE_HOMOSIG:
        ase_homosig_mpk_init(pp, &master->homosig);
        break;
    default:
        assert(0);
        abort();
    }
}

void
ase_mpk_clear(struct ase_pp_t *pp, struct ase_master_t *master,
              enum ase_type_e type)
{
    switch (type) {
    case ASE_HOMOSIG:
        ase_homosig_mpk_clear(pp, &master->homosig);
        break;
    default:
        assert(0);
        abort();
    }
}

void
ase_pk_init(struct ase_pp_t *pp, struct ase_pk_t *pk, enum ase_type_e type)
{
    switch (type) {
    case ASE_HOMOSIG:
        ase_homosig_pk_init(pp, &pk->homosig);
        break;
    default:
        assert(0);
        abort();
    }
}

void
ase_pk_clear(const struct ase_pp_t *pp, struct ase_pk_t *pk,
             enum ase_type_e type)
{
    switch (type) {
    case ASE_HOMOSIG:
        ase_homosig_pk_clear(pp, &pk->homosig);
        break;
    default:
        assert(0);
        abort();
    }
}

void
ase_sk_init(struct ase_pp_t *pp, struct ase_sk_t *sk, enum ase_type_e type)
{
    switch (type) {
    case ASE_HOMOSIG:
        ase_homosig_sk_init(pp, &sk->homosig);
        break;
    default:
        assert(0);
        abort();
    }
}

void
ase_sk_clear(const struct ase_pp_t *pp, struct ase_sk_t *sk,
             enum ase_type_e type)
{
    switch (type) {
    case ASE_HOMOSIG:
        ase_homosig_sk_clear(pp, &sk->homosig);
        break;
    default:
        assert(0);
        abort();
    }
}

void
ase_ctxt_init(struct ase_pp_t *pp, struct ase_ctxt_t *ctxt,
              enum ase_type_e type)
{
    switch (type) {
    case ASE_HOMOSIG:
        ase_homosig_ctxt_init(pp, &ctxt->homosig);
        break;
    default:
        assert(0);
        abort();
    }
}

void
ase_ctxt_clear(struct ase_pp_t *pp, struct ase_ctxt_t *ctxt,
               enum ase_type_e type)
{
    switch (type) {
    case ASE_HOMOSIG:
        ase_homosig_ctxt_clear(pp, &ctxt->homosig);
        break;
    default:
        assert(0);
        abort();
    }
}

void
ase_mpk_print(const struct ase_pp_t *pp, struct ase_master_t *master,
              enum ase_type_e type)
{
    switch (type) {
    case ASE_HOMOSIG:
        ase_homosig_mpk_print(pp, &master->homosig);
        break;
    default:
        assert(0);
        abort();
    }
}

void
ase_pk_print(const struct ase_pp_t *pp, struct ase_pk_t *pk,
             enum ase_type_e type)
{
    switch (type) {
    case ASE_HOMOSIG:
        ase_homosig_pk_print(pp, &pk->homosig);
        break;
    default:
        assert(0);
        abort();
    }
}

void
ase_sk_print(const struct ase_pp_t *pp, struct ase_sk_t *sk,
             enum ase_type_e type)
{
    switch (type) {
    case ASE_HOMOSIG:
        ase_homosig_sk_print(pp, &sk->homosig);
        break;
    default:
        assert(0);
        abort();
    }
}

void
ase_ctxt_print(const struct ase_pp_t *pp, struct ase_ctxt_t *ctxt,
               enum ase_type_e type)
{
    switch (type) {
    case ASE_HOMOSIG:
        ase_homosig_ctxt_print(pp, &ctxt->homosig);
        break;
    default:
        assert(0);
        abort();
    }
}

/* Send/receive functions */

int
ase_mpk_send(const struct ase_pp_t *pp, struct ase_master_t *master,
             FILE *f, enum ase_type_e type)
{
    switch (type) {
    case ASE_HOMOSIG:
        return ase_homosig_mpk_send(pp, &master->homosig, f);
        break;
    default:
        assert(0);
        abort();
    }
}

int 
ase_mpk_recv(struct ase_pp_t *pp, struct ase_master_t *master, FILE *f,
             enum ase_type_e type)
{
    switch (type) {
    case ASE_HOMOSIG:
        return ase_homosig_mpk_recv(pp, &master->homosig, f);
        break;
    default:
        assert(0);
        abort();
    }
}

int
ase_pk_send(const struct ase_pp_t *pp, struct ase_pk_t *pk, FILE *f,
            enum ase_type_e type)
{
    switch (type) {
    case ASE_HOMOSIG:
        return ase_homosig_pk_send(pp, &pk->homosig, f);
        break;
    default:
        assert(0);
        abort();
    }
}

int
ase_pk_recv(const struct ase_pp_t *pp, struct ase_pk_t *pk, FILE *f,
            enum ase_type_e type)
{
    switch (type) {
    case ASE_HOMOSIG:
        return ase_homosig_pk_recv(pp, &pk->homosig, f);
        break;
    default:
        assert(0);
        abort();
    }
}

int
ase_sk_send(const struct ase_pp_t *pp, struct ase_sk_t *sk, FILE *f,
            enum ase_type_e type)
{
    switch (type) {
    case ASE_HOMOSIG:
        return ase_homosig_sk_send(pp, &sk->homosig, f);
        break;
    default:
        assert(0);
        abort();
    }
}

int
ase_sk_recv(const struct ase_pp_t *pp, struct ase_sk_t *sk, FILE *f,
            enum ase_type_e type)
{
    switch (type) {
    case ASE_HOMOSIG:
        return ase_homosig_sk_recv(pp, &sk->homosig, f);
        break;
    default:
        assert(0);
        abort();
    }
}

int
ase_ctxt_send(const struct ase_pp_t *pp, struct ase_ctxt_t *ctxt, FILE *f,
              enum ase_type_e type)
{
    switch (type) {
    case ASE_HOMOSIG:
        return ase_homosig_ctxt_send(pp, &ctxt->homosig, f);
        break;
    default:
        assert(0);
        abort();
    }
}

int
ase_ctxt_recv(const struct ase_pp_t *pp, struct ase_ctxt_t *ctxt, FILE *f,
              enum ase_type_e type)
{
    switch (type) {
    case ASE_HOMOSIG:
        return ase_homosig_ctxt_recv(pp, &ctxt->homosig, f);
        break;
    default:
        assert(0);
        abort();
    }
}

/* Main ASE functions */

void
ase_gen(struct ase_pp_t *pp, struct ase_master_t *msk,
        struct ase_pk_t *pk, struct ase_sk_t *sk, const int *attrs,
        enum ase_type_e type)
{
    switch (type) {
    case ASE_HOMOSIG:
        ase_homosig_gen(pp, &msk->homosig, &pk->homosig, &sk->homosig, attrs);
        break;
    default:
        assert(0);
        abort();
    }
}

int
ase_vrfy(struct ase_pp_t *pp, struct ase_master_t *mpk, struct ase_pk_t *pk,
         enum ase_type_e type)
{
    switch (type) {
    case ASE_HOMOSIG:
        return ase_homosig_vrfy(pp, &mpk->homosig, &pk->homosig);
        break;
    default:
        assert(0);
        abort();
    }
}

void
ase_enc(struct ase_pp_t *pp, struct ase_pk_t *pk, const int *attrs,
        struct ase_ctxt_t *ciphertext, g1_t *plaintext,
        const unsigned int *seed, enum ase_type_e type)
{
    switch (type) {
    case ASE_HOMOSIG:
        ase_homosig_enc(pp, &pk->homosig, attrs, &ciphertext->homosig,
                        plaintext, seed);
        break;
    default:
        assert(0);
        abort();
    }
}

void
ase_dec(struct ase_pp_t *pp, struct ase_sk_t *sk, g1_t *plaintext,
        struct ase_ctxt_t *ciphertext, const int *attrs, enum ase_type_e type)
{
    switch (type) {
    case ASE_HOMOSIG:
        ase_homosig_dec(pp, &sk->homosig, plaintext,
                               &ciphertext->homosig, attrs);
        break;
    default:
        assert(0);
        abort();
    }
}

void
ase_unlink(struct ase_pp_t *pp, struct ase_pk_t *rpk, struct ase_sk_t *rsk,
           struct ase_pk_t *pk, struct ase_sk_t *sk, enum ase_type_e type)
{
    switch (type) {
    case ASE_HOMOSIG:
        ase_homosig_unlink(pp, &rpk->homosig, &rsk->homosig,
                           &pk->homosig, &sk->homosig);
        break;
    default:
        assert(0);
        abort();
    }
}
