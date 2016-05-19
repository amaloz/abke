#include "ase_homosig.h"
#include "net.h"
#include "util.h"

#include <assert.h>

void
ase_homosig_master_init(struct ase_pp_t *pp, struct ase_homosig_master_t *master)
{
    bls_init(&master->gsig);
    bls_init(&master->hsig);
    bls_init(&master->usig);
    master->jsigs = calloc(pp->m, sizeof(struct bls_t));
    for (int i = 0; i < pp->m; ++i) {
        bls_init(&master->jsigs[i]);
    }
}

void
ase_homosig_master_clear(const struct ase_pp_t *pp,
                         struct ase_homosig_master_t *master)
{
    bls_clear(&master->gsig);
    bls_clear(&master->hsig);
    bls_clear(&master->usig);
    for (int i = 0; i < pp->m; ++i) {
        bls_clear(&master->jsigs[i]);
    }
    free(master->jsigs);
}

void
ase_homosig_mpk_init(struct ase_pp_t *pp, struct ase_homosig_master_t *master)
{
    bls_pk_init(&master->gsig);
    bls_pk_init(&master->hsig);
    bls_pk_init(&master->usig);
    master->jsigs = calloc(pp->m, sizeof(struct bls_t));
    for (int i = 0; i < pp->m; ++i) {
        bls_pk_init(&master->jsigs[i]);
    }
}

void
ase_homosig_mpk_clear(struct ase_pp_t *pp, struct ase_homosig_master_t *master)
{
    bls_pk_clear(&master->gsig);
    bls_pk_clear(&master->hsig);
    bls_pk_clear(&master->usig);
    for (int i = 0; i < pp->m; ++i) {
        bls_pk_clear(&master->jsigs[i]);
    }
    free(master->jsigs);
}

void
ase_homosig_pk_init(struct ase_pp_t *pp, struct ase_homosig_pk_t *pk)
{
    g1_new(pk->g);
    g1_new(pk->h);
    g1_new(pk->u);
    g1_new(pk->gsig);
    g1_new(pk->hsig);
    g1_new(pk->usig);
    g1_get_gen(pk->g);
    g1_get_gen(pk->h);
    g1_get_gen(pk->u);
    g1_get_gen(pk->gsig);
    g1_get_gen(pk->hsig);
    g1_get_gen(pk->usig);
    pk->es = calloc(pp->m, sizeof(g1_t));
    pk->esigs = calloc(pp->m, sizeof(g1_t));
    for (int i = 0; i < pp->m; ++i) {
        g1_new(pk->es[i]);
        g1_new(pk->esigs[i]);
        g1_get_gen(pk->es[i]);
        g1_get_gen(pk->esigs[i]);
    }
}

void
ase_homosig_pk_clear(const struct ase_pp_t *pp, struct ase_homosig_pk_t *pk)
{
    g1_free(pk->g);
    g1_free(pk->h);
    g1_free(pk->u);
    g1_free(pk->gsig);
    g1_free(pk->hsig);
    g1_free(pk->usig);
    for (int i = 0; i < pp->m; ++i) {
        g1_free(pk->es[i]);
        g1_free(pk->esigs[i]);
    }
    free(pk->es);
    free(pk->esigs);
}

void
ase_homosig_sk_init(struct ase_pp_t *pp, struct ase_homosig_sk_t *sk)
{
    sk->rs = calloc(pp->m, sizeof(bn_t));
    for (int i = 0; i < pp->m; ++i) {
        bn_new(sk->rs[i]);
        g1_get_ord(sk->rs[i]);
    }
}

void
ase_homosig_sk_clear(const struct ase_pp_t *pp, struct ase_homosig_sk_t *sk)
{
    for (int i = 0; i < pp->m; ++i) {
        bn_free(sk->rs[i]);
    }
    free(sk->rs);
}

void
ase_homosig_ctxt_init(struct ase_pp_t *pp, struct ase_homosig_ctxt_t *ctxt)
{
    g1_new(ctxt->g);
    g1_new(ctxt->h);
    g1_get_gen(ctxt->g);
    g1_get_gen(ctxt->h);
    ctxt->c2s = calloc(2 * pp->m, sizeof(g1_t));
    for (int i = 0; i < 2 * pp->m; ++i) {
        g1_new(ctxt->c2s[i]);
        g1_get_gen(ctxt->c2s[i]);
    }
}

void
ase_homosig_ctxt_clear(struct ase_pp_t *pp, struct ase_homosig_ctxt_t *ctxt)
{
    g1_free(ctxt->g);
    g1_free(ctxt->h);
    for (int i = 0; i < 2 * pp->m; ++i) {
        g1_free(ctxt->c2s[i]);
    }
    free(ctxt->c2s);
}

void
ase_homosig_mpk_print(const struct ase_pp_t *pp, struct ase_homosig_master_t *master)
{
    printf("Master public key:\n");
    printf("--------------------------------\n");
    bls_pk_print(&master->gsig);
    bls_pk_print(&master->hsig);
    bls_pk_print(&master->usig);
    for (int i = 0; i < pp->m; ++i) {
        bls_pk_print(&master->jsigs[i]);
    }
    printf("--------------------------------\n");
}

void
ase_homosig_pk_print(const struct ase_pp_t *pp, struct ase_homosig_pk_t *pk)
{
    printf("Public key:\n");
    printf("--------------------------------\n");
    g1_print(pk->g);
    printf("\n");
    g1_print(pk->h);
    printf("\n");
    g1_print(pk->u);
    printf("\n");
    g1_print(pk->gsig);
    printf("\n");
    g1_print(pk->hsig);
    printf("\n");
    g1_print(pk->usig);
    printf("\n");
    for (int i = 0; i < pp->m; ++i) {
        g1_print(pk->es[i]);
        printf("\n");
    }
    for (int i = 0; i < pp->m; ++i) {
        g1_print(pk->esigs[i]);
        printf("\n");
    }
    printf("--------------------------------\n");
}

void
ase_homosig_sk_print(const struct ase_pp_t *pp, struct ase_homosig_sk_t *sk)
{
    printf("Secret key:\n");
    printf("--------------------------------\n");
    for (int i = 0; i < pp->m; ++i) {
        bn_print(sk->rs[i]);
        printf("\n");
    }
    printf("--------------------------------\n");
}

void
ase_homosig_ctxt_print(const struct ase_pp_t *pp, struct ase_homosig_ctxt_t *ctxt)
{
    printf("Ciphertext:\n");
    printf("--------------------------------\n");
    g1_print(ctxt->g);
    printf("\n");
    g1_print(ctxt->h);
    printf("\n");
    for (int i = 0; i < 2 * pp->m; ++i) {
        g1_print(ctxt->c2s[i]);
        printf("\n");
    }
    printf("--------------------------------\n");
}

int
ase_homosig_mpk_send(const struct ase_pp_t *pp,
                     struct ase_homosig_master_t *master, FILE *f)
{
    size_t length = 0, p = 0;
    unsigned char *buf;
    int res = 0;

    length += bls_pk_length(&master->gsig);
    length += bls_pk_length(&master->hsig);
    length += bls_pk_length(&master->usig);
    for (int i = 0; i < pp->m; ++i) {
        length += bls_pk_length(&master->jsigs[i]);
    }
    if ((buf = malloc(length)) == NULL)
        return -1;
    p += bls_pk_to_bytes(buf + p, &master->gsig);
    p += bls_pk_to_bytes(buf + p, &master->hsig);
    p += bls_pk_to_bytes(buf + p, &master->usig);
    for (int i = 0; i < pp->m; ++i) {
        p += bls_pk_to_bytes(buf + p, &master->jsigs[i]);
    }
    net_send(f, &length, sizeof length);
    net_send(f, buf, length);

    free(buf);
    return res;
}

int 
ase_homosig_mpk_recv(struct ase_pp_t *pp, struct ase_homosig_master_t *master,
                     FILE *f)
{
    size_t length, p = 0;
    unsigned char *buf;
    int res = 0;

    net_recv(f, &length, sizeof length);
    if ((buf = malloc(length)) == NULL)
        return -1;
    (void) net_recv(f, buf, length);
    p += bls_pk_from_bytes(&master->gsig, buf + p);
    p += bls_pk_from_bytes(&master->hsig, buf + p);
    p += bls_pk_from_bytes(&master->usig, buf + p);
    for (int i = 0; i < pp->m; ++i) {
        p += bls_pk_from_bytes(&master->jsigs[i], buf + p);
    }

    free(buf);
    return res;
}

int
ase_homosig_pk_send(const struct ase_pp_t *pp, struct ase_homosig_pk_t *pk,
                    FILE *f)
{
    size_t length = 0, p = 0;
    unsigned char *buf;
    int res = 0;

    length += g1_length_in_bytes_(pk->g);
    length += g1_length_in_bytes_(pk->h);
    length += g1_length_in_bytes_(pk->u);
    length += g1_length_in_bytes_(pk->gsig);
    length += g1_length_in_bytes_(pk->hsig);
    length += g1_length_in_bytes_(pk->usig);
    for (int i = 0; i < pp->m; ++i) {
        length += g1_length_in_bytes_(pk->es[i]);
        length += g1_length_in_bytes_(pk->esigs[i]);
    }
    if ((buf = malloc(length)) == NULL)
        return -1;
    p += g1_to_bytes_(buf + p, pk->g);
    p += g1_to_bytes_(buf + p, pk->h);
    p += g1_to_bytes_(buf + p, pk->u);
    p += g1_to_bytes_(buf + p, pk->gsig);
    p += g1_to_bytes_(buf + p, pk->hsig);
    p += g1_to_bytes_(buf + p, pk->usig);
    for (int i = 0; i < pp->m; ++i) {
        p += g1_to_bytes_(buf + p, pk->es[i]);
        p += g1_to_bytes_(buf + p, pk->esigs[i]);
    }
    net_send(f, &length, sizeof length);
    net_send(f, buf, length);

    free(buf);
    return res;
}

int
ase_homosig_pk_recv(const struct ase_pp_t *pp, struct ase_homosig_pk_t *pk,
                    FILE *f)
{
    size_t length, p = 0;
    unsigned char *buf;
    int res = 0;

    net_recv(f, &length, sizeof length);
    if ((buf = malloc(length)) == NULL)
        return -1;
    net_recv(f, buf, length);
    p += g1_from_bytes_(pk->g, buf + p);
    p += g1_from_bytes_(pk->h, buf + p);
    p += g1_from_bytes_(pk->u, buf + p);
    p += g1_from_bytes_(pk->gsig, buf + p);
    p += g1_from_bytes_(pk->hsig, buf + p);
    p += g1_from_bytes_(pk->usig, buf + p);
    for (int i = 0; i < pp->m; ++i) {
        p += g1_from_bytes_(pk->es[i], buf + p);
        p += g1_from_bytes_(pk->esigs[i], buf + p);
    }

    free(buf);
    return res;
}

int
ase_homosig_sk_send(const struct ase_pp_t *pp, struct ase_homosig_sk_t *sk,
                    FILE *f)
{
    size_t length = 0, p = 0;
    unsigned char *buf;
    int res = 0;

    bn_t ord;

    bn_new(ord);
    g1_get_ord(ord);

    for (int i = 0; i < pp->m; ++i) {
        length += bn_size_bin(sk->rs[i]);
    }
    if ((buf = calloc(length * 8, sizeof(char))) == NULL)
        return -1;
    for (int i = 0; i < pp->m; ++i) {
        p += bn_to_bytes_(((uint64_t *) buf) + p, sk->rs[i]);
    }
    net_send(f, &length, sizeof length);
    net_send(f, buf, length * 8);

    free(buf);
    return res;
}

int
ase_homosig_sk_recv(const struct ase_pp_t *pp, struct ase_homosig_sk_t *sk,
                    FILE *f)
{
    size_t length, p = 0;
    unsigned char *buf;
    int res = 0;

    net_recv(f, &length, sizeof length);
    if ((buf = calloc(length * 8, sizeof(char))) == NULL)
        return -1;
    net_recv(f, buf, length * 8);

    for (int i = 0; i < pp->m; ++i) {
        p += bn_from_bytes_(sk->rs[i], ((uint64_t *) buf) + p);
    }

    free(buf);
    return res;
}

int
ase_homosig_ctxt_send(const struct ase_pp_t *pp, struct ase_homosig_ctxt_t *ctxt,
                      FILE *f)
{
    size_t length = 0, p = 0;
    unsigned char *buf;
    int res = 0;

    length += g1_length_in_bytes_(ctxt->g);
    length += g1_length_in_bytes_(ctxt->h);
    for (int i = 0; i < 2 * pp->m; ++i) {
        length += g1_length_in_bytes_(ctxt->c2s[i]);
    }
    if ((buf = malloc(length)) == NULL)
        return -1;
    p += g1_to_bytes_(buf + p, ctxt->g);
    p += g1_to_bytes_(buf + p, ctxt->h);
    for (int i = 0; i < 2 * pp->m; ++i) {
        p += g1_to_bytes_(buf + p, ctxt->c2s[i]);
    }
    net_send(f, &length, sizeof length);
    net_send(f, buf, length);

    free(buf);
    return res;
}

int
ase_homosig_ctxt_recv(const struct ase_pp_t *pp, struct ase_homosig_ctxt_t *ctxt,
                      FILE *f)
{
    size_t length, p = 0;
    unsigned char *buf;
    int res = 0;

    net_recv(f, &length, sizeof length);
    if ((buf = malloc(length)) == NULL)
        return -1;
    net_recv(f, buf, length);

    p += g1_from_bytes_(ctxt->g, buf + p);
    p += g1_from_bytes_(ctxt->h, buf + p);
    for (int i = 0; i < 2 * pp->m; ++i) {
        p += g1_from_bytes_(ctxt->c2s[i], buf + p);
    }

    free(buf);
    return res;
}

void
ase_homosig_gen(struct ase_pp_t *pp, struct ase_homosig_master_t *msk,
                struct ase_homosig_pk_t *pk, struct ase_homosig_sk_t *sk,
                const int *attrs)
{
    g1_t tmp;
    bn_t ord;

    g1_new(tmp);
    bn_new(ord);
    g1_get_ord(ord);

    g1_rand(pk->g);
    g1_rand(pk->h);
    g1_rand(pk->u);
    bls_sign(&msk->gsig, pk->gsig, pk->g);
    bls_sign(&msk->hsig, pk->hsig, pk->h);
    bls_sign(&msk->usig, pk->usig, pk->u);

    for (int i = 0; i < pp->m; ++i) {
        bn_rand_mod(sk->rs[i], ord);
        switch (attrs[i]) {
        case 0:
            g1_mul_norm(pk->es[i], pk->g, sk->rs[i]);
            break;
        case 1:
            g1_mul_norm(pk->es[i], pk->h, sk->rs[i]);
            break;
        default:
            assert(0);
            abort();
        }
        g1_add_norm(tmp, pk->u, pk->es[i]);
        bls_sign(&msk->jsigs[i], pk->esigs[i], tmp);
    }

    g1_free(tmp);
    bn_free(ord);
}

int
ase_homosig_vrfy(struct ase_pp_t *pp, struct ase_homosig_master_t *mpk,
                 struct ase_homosig_pk_t *pk)
{
    g1_t tmp;
    int res = 0;

    g1_new(tmp);

    if (!bls_verify(&mpk->gsig, pk->gsig, pk->g))
        goto cleanup;
    if (!bls_verify(&mpk->hsig, pk->hsig, pk->h))
        goto cleanup;
    if (!bls_verify(&mpk->usig, pk->usig, pk->u))
        goto cleanup;
    for (int i = 0; i < pp->m; ++i) {
        g1_add_norm(tmp, pk->u, pk->es[i]);
        if (!bls_verify(&mpk->jsigs[i], pk->esigs[i], tmp))
            goto cleanup;
    }
    res = 1;

cleanup:
    g1_free(tmp);
    return res;
}

void
ase_homosig_enc(struct ase_pp_t *pp, struct ase_homosig_pk_t *pk,
                const int *attrs, struct ase_homosig_ctxt_t *ciphertext,
                g1_t *plaintext, const unsigned int *seed)
{
    bn_t s, t, ord;
    g1_t tmp;

    bn_new(ord);
    bn_new(s);
    bn_new(t);

    g1_new(tmp);
    g1_get_ord(ord);

    if (seed) {
        rand_clean();
        rand_init();
        /* pbc_random_set_deterministic(*seed); */
    }

    bn_rand_mod(s, ord);
    bn_rand_mod(t, ord);
    g1_mul_norm(ciphertext->g, pk->g, s);
    g1_mul_norm(ciphertext->h, pk->h, t);

    for (int i = 0; i < pp->m; ++i) {
        if (attrs == NULL || attrs[i] == 0) {
            g1_mul_norm(tmp, pk->es[i], s);
            g1_add_norm(ciphertext->c2s[2 * i], tmp, plaintext[2 * i]);
        }
        if (attrs == NULL || attrs[i] == 1) {
            g1_mul_norm(tmp, pk->es[i], t);
            g1_add_norm(ciphertext->c2s[2 * i + 1], tmp, plaintext[2 * i + 1]);
        }
    }

    if (seed) {
        rand_clean();
        rand_init();
        /* pbc_random_set_file("/dev/urandom"); */
    }

    bn_free(ord);
    bn_free(s);
    bn_free(t);
    g1_free(tmp);
}

void
ase_homosig_dec(struct ase_pp_t *pp, struct ase_homosig_sk_t *sk,
                g1_t *plaintext, struct ase_homosig_ctxt_t *ciphertext,
                const int *attrs)
{
    g1_t tmp;

    g1_new(tmp);

    for (int i = 0; i < pp->m; ++i) {
        if (attrs[i]) {
            g1_mul_norm(tmp, ciphertext->h, sk->rs[i]);
        } else {
            g1_mul_norm(tmp, ciphertext->g, sk->rs[i]);
        }
        g1_sub_norm(plaintext[i], ciphertext->c2s[2 * i + attrs[i]], tmp);
    }

    g1_free(tmp);
}

void
ase_homosig_unlink(struct ase_pp_t *pp, struct ase_homosig_pk_t *rpk,
                   struct ase_homosig_sk_t *rsk, struct ase_homosig_pk_t *pk,
                   struct ase_homosig_sk_t *sk)
{
    bn_t r;
    bn_t ord;

    bn_new(r);
    bn_new(ord);
    g1_get_ord(ord);

    bn_rand_mod(r, ord);

    g1_mul_norm(rpk->g, pk->g, r);
    g1_mul_norm(rpk->h, pk->h, r);
    g1_mul_norm(rpk->u, pk->u, r);
    g1_mul_norm(rpk->gsig, pk->gsig, r);
    g1_mul_norm(rpk->hsig, pk->hsig, r);
    g1_mul_norm(rpk->usig, pk->usig, r);
    for (int i = 0; i < pp->m; ++i) {
        g1_mul_norm(rpk->es[i], pk->es[i], r);
        g1_mul_norm(rpk->esigs[i], pk->esigs[i], r);
        bn_copy(rsk->rs[i], sk->rs[i]);
    }

    bn_free(r);
    bn_free(ord);
}
