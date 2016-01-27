#include "apse.h"
#include "net.h"

#include <assert.h>

void
apse_pp_init(struct apse_pp_t *pp, int m, const char *fname, const block *aeskey)
{
    char param[1024];
    size_t count;
    FILE *f;

    pp->m = m;

    if ((f = fopen(fname, "r")) == NULL) {
        pbc_die("fopen");
    }

    count = fread(param, sizeof(char), 1024, f);
    if (!count) {
        pbc_die("fread");
    }
    (void) pairing_init_set_buf(pp->pairing, param, count);
    pp->aeskey = aeskey ? *aeskey : randomBlock();

    fclose(f);
}

void
apse_pp_clear(struct apse_pp_t *pp)
{
    pairing_clear(pp->pairing);
}

void
apse_master_init(struct apse_pp_t *pp, struct apse_master_t *master)
{
    bls_init(&master->gsig, pp->pairing);
    bls_init(&master->hsig, pp->pairing);
    bls_init(&master->usig, pp->pairing);
    master->jsigs = calloc(pp->m, sizeof(struct bls_t));
    for (int i = 0; i < pp->m; ++i) {
        bls_init(&master->jsigs[i], pp->pairing);
    }
}

void
apse_master_clear(const struct apse_pp_t *pp, struct apse_master_t *master)
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
apse_pk_init(struct apse_pp_t *pp, struct apse_pk_t *pk)
{
    element_init_G1(pk->g, pp->pairing);
    element_init_G1(pk->h, pp->pairing);
    element_init_G1(pk->u, pp->pairing);
    element_init_G1(pk->gsig, pp->pairing);
    element_init_G1(pk->hsig, pp->pairing);
    element_init_G1(pk->usig, pp->pairing);
    pk->es = calloc(pp->m, sizeof(element_t));
    pk->esigs = calloc(pp->m, sizeof(element_t));
    for (int i = 0; i < pp->m; ++i) {
        element_init_G1(pk->es[i], pp->pairing);
        element_init_G1(pk->esigs[i], pp->pairing);
    }
}

void
apse_pk_clear(const struct apse_pp_t *pp, struct apse_pk_t *pk)
{
    element_clear(pk->g);
    element_clear(pk->h);
    element_clear(pk->u);
    element_clear(pk->gsig);
    element_clear(pk->hsig);
    element_clear(pk->usig);
    for (int i = 0; i < pp->m; ++i) {
        element_clear(pk->es[i]);
        element_clear(pk->esigs[i]);
    }
    free(pk->es);
    free(pk->esigs);
}

void
apse_sk_init(struct apse_pp_t *pp, struct apse_sk_t *sk)
{
    sk->rs = calloc(pp->m, sizeof(element_t));
    for (int i = 0; i < pp->m; ++i) {
        element_init_Zr(sk->rs[i], pp->pairing);
    }
}

void
apse_sk_clear(const struct apse_pp_t *pp, struct apse_sk_t *sk)
{
    for (int i = 0; i < pp->m; ++i) {
        element_clear(sk->rs[i]);
    }
    free(sk->rs);
}

/* Send/receive functions */

static void
send_bls_pk(struct bls_t *bls, int fd)
{
    net_send_element(fd, bls->g);
    net_send_element(fd, bls->h);
    net_send_element(fd, bls->pubkey);
}

void
apse_mpk_send(const struct apse_pp_t *pp, struct apse_master_t *master,
              int fd)
{
    send_bls_pk(&master->gsig, fd);
    send_bls_pk(&master->hsig, fd);
    send_bls_pk(&master->usig, fd);
    for (int i = 0; i < pp->m; ++i) {
        send_bls_pk(&master->jsigs[i], fd);
    }
}

static void
recv_bls_pk(struct bls_t *bls, int fd)
{
    net_recv_element(fd, bls->g);
    net_recv_element(fd, bls->h);
    net_recv_element(fd, bls->pubkey);
}

void
apse_mpk_recv(const struct apse_pp_t *pp, struct apse_master_t *master, int fd)
{
    recv_bls_pk(&master->gsig, fd);
    recv_bls_pk(&master->hsig, fd);
    recv_bls_pk(&master->usig, fd);
    for (int i = 0; i < pp->m; ++i) {
        recv_bls_pk(&master->jsigs[i], fd);
    }
}

void
apse_pk_send(const struct apse_pp_t *pp, struct apse_pk_t *pk, int fd)
{
    net_send_element(fd, pk->g);
    net_send_element(fd, pk->h);
    net_send_element(fd, pk->u);
    net_send_element(fd, pk->gsig);
    net_send_element(fd, pk->hsig);
    net_send_element(fd, pk->usig);
    for (int i = 0; i < pp->m; ++i) {
        net_send_element(fd, pk->es[i]);
    }
    for (int i = 0; i < pp->m; ++i) {
        net_send_element(fd, pk->esigs[i]);
    }
}

void
apse_pk_recv(const struct apse_pp_t *pp, struct apse_pk_t *pk, int fd)
{
    net_recv_element(fd, pk->g);
    net_recv_element(fd, pk->h);
    net_recv_element(fd, pk->u);
    net_recv_element(fd, pk->gsig);
    net_recv_element(fd, pk->hsig);
    net_recv_element(fd, pk->usig);
    for (int i = 0; i < pp->m; ++i) {
        net_recv_element(fd, pk->es[i]);
    }
    for (int i = 0; i < pp->m; ++i) {
        net_recv_element(fd, pk->esigs[i]);
    }
}

void
apse_sk_send(const struct apse_pp_t *pp, struct apse_sk_t *sk, int fd)
{
    for (int i = 0; i < pp->m; ++i) {
        net_send_element(fd, sk->rs[i]);
    }
}

void
apse_sk_recv(const struct apse_pp_t *pp, struct apse_sk_t *sk, int fd)
{
    for (int i = 0; i < pp->m; ++i) {
        net_recv_element(fd, sk->rs[i]);
    }
}

/* Print APSE functions */

void
apse_pp_print(struct apse_pp_t *pp)
{
    printf("m = %d\n", pp->m);
}

void
apse_pk_print(struct apse_pp_t *pp, struct apse_pk_t *pk)
{
    element_printf("g = %B\n", pk->g);
    element_printf("h = %B\n", pk->h);
    element_printf("u = %B\n", pk->u);
    element_printf("gsig = %B\n", pk->gsig);
    element_printf("hsig = %B\n", pk->hsig);
    element_printf("usig = %B\n", pk->usig);
    for (int i = 0; i < pp->m; ++i) {
        element_printf("es[%d] = %B\n", i, pk->es[i]);
        element_printf("esigs[%d] = %B\n", i, pk->esigs[i]);
    }
}

void
apse_sk_print(struct apse_pp_t *pp, struct apse_sk_t *sk)
{
    for (int i = 0; i < pp->m; ++i) {
        element_printf("rs[%d] = %B\n", i, sk->rs[i]);
    }
}


/* Main APSE functions */

void
apse_gen(struct apse_pp_t *pp, struct apse_master_t *msk,
         struct apse_pk_t *pk, struct apse_sk_t *sk, const int *attrs)
{
    element_t tmp;

    element_init_G1(tmp, pp->pairing);

    element_random(pk->g);
    element_random(pk->h);
    element_random(pk->u);
    bls_sign(&msk->gsig, pk->gsig, pk->g);
    bls_sign(&msk->hsig, pk->hsig, pk->h);
    bls_sign(&msk->usig, pk->usig, pk->u);

    for (int i = 0; i < pp->m; ++i) {
        element_random(sk->rs[i]);
        switch (attrs[i]) {
        case 0:
            element_pow_zn(pk->es[i], pk->g, sk->rs[i]);
            break;
        case 1:
            element_pow_zn(pk->es[i], pk->h, sk->rs[i]);
            break;
        default:
            assert(0);
            abort();
        }
        element_mul(tmp, pk->u, pk->es[i]);
        bls_sign(&msk->jsigs[i], pk->esigs[i], tmp);
    }

    element_clear(tmp);
}

int
apse_vrfy(struct apse_pp_t *pp, struct apse_master_t *mpk, struct apse_pk_t *pk)
{
    element_t tmp;
    int res = 0;

    element_init_G1(tmp, pp->pairing);

    if (!bls_verify(&mpk->gsig, pk->gsig, pk->g, pp->pairing)) {
        printf("gsig failed\n");
        goto cleanup;
    }
    if (!bls_verify(&mpk->hsig, pk->hsig, pk->h, pp->pairing))
        goto cleanup;
    if (!bls_verify(&mpk->usig, pk->usig, pk->u, pp->pairing))
        goto cleanup;
    for (int i = 0; i < pp->m; ++i) {
        element_mul(tmp, pk->u, pk->es[i]);
        if (!bls_verify(&mpk->jsigs[i], pk->esigs[i], tmp, pp->pairing))
            goto cleanup;
    }
    res = 1;

cleanup:
    element_clear(tmp);
    return res;
}

void
apse_enc(struct apse_pp_t *pp, struct apse_pk_t *pk,
         struct apse_ctxt_elem_t *ciphertext, block *plaintext)
{
    element_t s;
    element_t c0a, c0b, c1a, c1b;
    element_t h;

    element_init_Zr(s, pp->pairing);
    element_init_G1(c0a, pp->pairing);
    element_init_G1(c0b, pp->pairing);
    element_init_G1(c1a, pp->pairing);
    element_init_G1(c1b, pp->pairing);
    element_init_G1(h, pp->pairing);

    for (int i = 0; i < pp->m; ++i) {
        element_random(s);
        element_pow_zn(ciphertext[2 * i].ca, pk->g, s);
        element_pow_zn(ciphertext[2 * i].cb, pk->es[i], s);
        element_from_hash(h, &plaintext[2 * i], 16);
        element_mul(ciphertext[2 * i].cb, ciphertext[2 * i].cb, h);

        element_random(s);
        element_pow_zn(ciphertext[2 * i + 1].ca, pk->h, s);
        element_pow_zn(ciphertext[2 * i + 1].cb, pk->es[i], s);
        element_from_hash(h, &plaintext[2 * i + 1], 16);
        element_mul(ciphertext[2 * i + 1].cb, ciphertext[2 * i + 1].cb, h);
    }
}

void
apse_dec(struct apse_pp_t *pp, struct apse_sk_t *sk, block *plaintext,
         struct apse_ctxt_elem_t *ciphertext, const int *attrs)
{
    element_t tmp;

    element_init_G1(tmp, pp->pairing);

    for (int i = 0; i < pp->m; ++i) {
        struct apse_ctxt_elem_t *elem;
        switch (attrs[i]) {
        case 0:
            elem = &ciphertext[2 * i];
            break;
        case 1:
            elem = &ciphertext[2 * i + 1];
            break;
        default:
            assert(0);
            abort();
        }
        element_pow_zn(tmp, elem->ca, sk->rs[i]);
        element_div(tmp, elem->cb, tmp);
        /* TODO: convert tmp -> block */
    }

    element_clear(tmp);
}

void
apse_unlink(struct apse_pp_t *pp, struct apse_pk_t *rpk, struct apse_sk_t *rsk,
            struct apse_pk_t *pk, struct apse_sk_t *sk)
{
    element_t r;

    element_init_Zr(r, pp->pairing);
    element_random(r);

    element_pow_zn(rpk->g, pk->g, r);
    element_pow_zn(rpk->h, pk->h, r);
    element_pow_zn(rpk->u, pk->u, r);
    element_pow_zn(rpk->gsig, pk->gsig, r);
    element_pow_zn(rpk->hsig, pk->hsig, r);
    element_pow_zn(rpk->usig, pk->usig, r);
    for (int i = 0; i < pp->m; ++i) {
        element_pow_zn(rpk->es[i], pk->es[i], r);
        element_pow_zn(rpk->esigs[i], pk->esigs[i], r);
    }

    for (int i = 0; i < pp->m; ++i) {
        element_mul(rsk->rs[i], sk->rs[i], r);
    }

    element_clear(r);
}
