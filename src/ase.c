#include "ase.h"
#include "net.h"
#include "util.h"

#include <assert.h>

int
ase_pp_init(struct ase_pp_t *pp, int m, const char *fname)
{
    char *param;
    size_t count, fsize;
    FILE *f;
    int res;

    pp->m = m;

    if ((f = fopen(fname, "r")) == NULL) {
        pbc_die("fopen");
    }

    fsize = filesize(fname);
    param = malloc(fsize);

    count = fread(param, sizeof(char), fsize, f);
    if (!count) {
        pbc_die("fread");
    }
    res = pairing_init_set_buf(pp->pairing, param, count);

    free(param);
    fclose(f);

    return res;
}

void
ase_pp_clear(struct ase_pp_t *pp)
{
    pairing_clear(pp->pairing);
}

void
ase_master_init(struct ase_pp_t *pp, struct ase_master_t *master)
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
ase_master_clear(const struct ase_pp_t *pp, struct ase_master_t *master)
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
ase_mpk_init(struct ase_pp_t *pp, struct ase_master_t *master)
{
    bls_pk_init(&master->gsig, pp->pairing);
    bls_pk_init(&master->hsig, pp->pairing);
    bls_pk_init(&master->usig, pp->pairing);
    master->jsigs = calloc(pp->m, sizeof(struct bls_t));
    for (int i = 0; i < pp->m; ++i) {
        bls_pk_init(&master->jsigs[i], pp->pairing);
    }
}

void
ase_mpk_clear(struct ase_pp_t *pp, struct ase_master_t *master)
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
ase_pk_init(struct ase_pp_t *pp, struct ase_pk_t *pk)
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
ase_pk_clear(const struct ase_pp_t *pp, struct ase_pk_t *pk)
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
ase_sk_init(struct ase_pp_t *pp, struct ase_sk_t *sk)
{
    sk->rs = calloc(pp->m, sizeof(element_t));
    for (int i = 0; i < pp->m; ++i) {
        element_init_Zr(sk->rs[i], pp->pairing);
    }
}

void
ase_sk_clear(const struct ase_pp_t *pp, struct ase_sk_t *sk)
{
    for (int i = 0; i < pp->m; ++i) {
        element_clear(sk->rs[i]);
    }
    free(sk->rs);
}

void
ase_ctxt_init(struct ase_pp_t *pp, struct ase_ctxt_t *ctxt)
{
    element_init_G1(ctxt->g, pp->pairing);
    element_init_G1(ctxt->h, pp->pairing);
    ctxt->c2s = calloc(2 * pp->m, sizeof(element_t));
    for (int i = 0; i < 2 * pp->m; ++i) {
        element_init_G1(ctxt->c2s[i], pp->pairing);
    }
}

void
ase_ctxt_clear(struct ase_pp_t *pp, struct ase_ctxt_t *ctxt)
{
    element_clear(ctxt->g);
    element_clear(ctxt->h);
    for (int i = 0; i < 2 * pp->m; ++i) {
        element_clear(ctxt->c2s[i]);
    }
    free(ctxt->c2s);
}

/* Send/receive functions */

int
ase_mpk_send(const struct ase_pp_t *pp, struct ase_master_t *master,
              int fd)
{
    size_t length = 0, p = 0;
    unsigned char *buf;
    int res = 0;

    length += element_length_in_bytes_(master->gsig.g);
    length += element_length_in_bytes_(master->gsig.h);
    length += element_length_in_bytes_(master->gsig.pubkey);
    length += element_length_in_bytes_(master->hsig.g);
    length += element_length_in_bytes_(master->hsig.h);
    length += element_length_in_bytes_(master->hsig.pubkey);
    length += element_length_in_bytes_(master->usig.g);
    length += element_length_in_bytes_(master->usig.h);
    length += element_length_in_bytes_(master->usig.pubkey);
    for (int i = 0; i < pp->m; ++i) {
        length += element_length_in_bytes_(master->jsigs[i].g);
        length += element_length_in_bytes_(master->jsigs[i].h);
        length += element_length_in_bytes_(master->jsigs[i].pubkey);
        
    }
    if ((buf = malloc(length)) == NULL)
        return -1;
    p += element_to_bytes_(buf + p, master->gsig.g);
    p += element_to_bytes_(buf + p, master->gsig.h);
    p += element_to_bytes_(buf + p, master->gsig.pubkey);
    p += element_to_bytes_(buf + p, master->hsig.g);
    p += element_to_bytes_(buf + p, master->hsig.h);
    p += element_to_bytes_(buf + p, master->hsig.pubkey);
    p += element_to_bytes_(buf + p, master->usig.g);
    p += element_to_bytes_(buf + p, master->usig.h);
    p += element_to_bytes_(buf + p, master->usig.pubkey);
    for (int i = 0; i < pp->m; ++i) {
        p += element_to_bytes_(buf + p, master->jsigs[i].g);
        p += element_to_bytes_(buf + p, master->jsigs[i].h);
        p += element_to_bytes_(buf + p, master->jsigs[i].pubkey);
    }
    if ((res = net_send(fd, &length, sizeof length, 0)) == -1)
        goto cleanup;
    res = net_send(fd, buf, length, 0);
cleanup:
    free(buf);
    return res;
}

int 
ase_mpk_recv(struct ase_pp_t *pp, struct ase_master_t *master, int fd)
{
    size_t length, p = 0;
    unsigned char *buf;
    int res = 0;

    if ((res = net_recv(fd, &length, sizeof length, 0)) == -1)
        return -1;
    if ((buf = malloc(length)) == NULL)
        return -1;
    if ((res = net_recv(fd, buf, length, 0)) == -1)
        goto cleanup;
    p += element_from_bytes_(master->gsig.g, buf + p);
    p += element_from_bytes_(master->gsig.h, buf + p);
    p += element_from_bytes_(master->gsig.pubkey, buf + p);
    p += element_from_bytes_(master->hsig.g, buf + p);
    p += element_from_bytes_(master->hsig.h, buf + p);
    p += element_from_bytes_(master->hsig.pubkey, buf + p);
    p += element_from_bytes_(master->usig.g, buf + p);
    p += element_from_bytes_(master->usig.h, buf + p);
    p += element_from_bytes_(master->usig.pubkey, buf + p);
    for (int i = 0; i < pp->m; ++i) {
        p += element_from_bytes_(master->jsigs[i].g, buf + p);
        p += element_from_bytes_(master->jsigs[i].h, buf + p);
        p += element_from_bytes_(master->jsigs[i].pubkey, buf + p);
    }
cleanup:
    free(buf);
    return res;
}

int
ase_pk_send(const struct ase_pp_t *pp, struct ase_pk_t *pk, int fd)
{
    size_t length = 0, p = 0;
    unsigned char *buf;
    int res = 0;

    length += element_length_in_bytes_(pk->g);
    length += element_length_in_bytes_(pk->h);
    length += element_length_in_bytes_(pk->u);
    length += element_length_in_bytes_(pk->gsig);
    length += element_length_in_bytes_(pk->hsig);
    length += element_length_in_bytes_(pk->usig);
    for (int i = 0; i < pp->m; ++i) {
        length += element_length_in_bytes_(pk->es[i]);
        length += element_length_in_bytes_(pk->esigs[i]);
    }
    if ((buf = malloc(length)) == NULL)
        return -1;
    p += element_to_bytes_(buf + p, pk->g);
    p += element_to_bytes_(buf + p, pk->h);
    p += element_to_bytes_(buf + p, pk->u);
    p += element_to_bytes_(buf + p, pk->gsig);
    p += element_to_bytes_(buf + p, pk->hsig);
    p += element_to_bytes_(buf + p, pk->usig);
    for (int i = 0; i < pp->m; ++i) {
        p += element_to_bytes_(buf + p, pk->es[i]);
    }
    for (int i = 0; i < pp->m; ++i) {
        p += element_to_bytes_(buf + p, pk->esigs[i]);
    }
    if ((res = net_send(fd, &length, sizeof length, 0)) == -1)
        goto cleanup;
    res = net_send(fd, buf, length, 0);
cleanup:
    free(buf);
    return res;
}

int
ase_pk_recv(const struct ase_pp_t *pp, struct ase_pk_t *pk, int fd)
{
    size_t length, p = 0;
    unsigned char *buf;
    int res = 0;

    if ((res = net_recv(fd, &length, sizeof length, 0)) == -1)
        return -1;
    if ((buf = malloc(length)) == NULL)
        return -1;
    if ((res = net_recv(fd, buf, length, 0)) == -1)
        goto cleanup;
    p += element_from_bytes_(pk->g, buf + p);
    p += element_from_bytes_(pk->h, buf + p);
    p += element_from_bytes_(pk->u, buf + p);
    p += element_from_bytes_(pk->gsig, buf + p);
    p += element_from_bytes_(pk->hsig, buf + p);
    p += element_from_bytes_(pk->usig, buf + p);
    for (int i = 0; i < pp->m; ++i) {
        p += element_from_bytes_(pk->es[i], buf + p);
    }
    for (int i = 0; i < pp->m; ++i) {
        p += element_from_bytes_(pk->esigs[i], buf + p);
    }

cleanup:
    free(buf);
    return res;
}

int
ase_sk_send(const struct ase_pp_t *pp, struct ase_sk_t *sk, int fd)
{
    size_t length = 0, p = 0;
    unsigned char *buf;
    int res = 0;

    for (int i = 0; i < pp->m; ++i) {
        length += element_length_in_bytes_(sk->rs[i]);
    }
    if ((buf = malloc(length)) == NULL)
        return -1;
    for (int i = 0; i < pp->m; ++i) {
        p += element_to_bytes_(buf + p, sk->rs[i]);
    }
    if ((res = net_send(fd, &length, sizeof length, 0)) == -1)
        goto cleanup;
    res = net_send(fd, buf, length, 0);
cleanup:
    free(buf);
    return res;
}

int
ase_sk_recv(const struct ase_pp_t *pp, struct ase_sk_t *sk, int fd)
{
    size_t length, p = 0;
    unsigned char *buf;
    int res = 0;

    if ((res = net_recv(fd, &length, sizeof length, 0)) == -1)
        return -1;
    if ((buf = malloc(length)) == NULL)
        return -1;
    if ((res = net_recv(fd, buf, length, 0)) == -1)
        goto cleanup;

    for (int i = 0; i < pp->m; ++i) {
        p += element_from_bytes_(sk->rs[i], buf + p);
    }
cleanup:
    free(buf);
    return res;
}

int
ase_ctxt_send(const struct ase_pp_t *pp, struct ase_ctxt_t *ctxt, int fd)
{
    size_t length = 0, p = 0;
    unsigned char *buf;
    int res = 0;

    length += element_length_in_bytes_(ctxt->g);
    length += element_length_in_bytes_(ctxt->h);
    for (int i = 0; i < 2 * pp->m; ++i) {
        length += element_length_in_bytes_(ctxt->c2s[i]);
    }
    if ((buf = malloc(length)) == NULL)
        return -1;
    p += element_to_bytes_(buf + p, ctxt->g);
    p += element_to_bytes_(buf + p, ctxt->h);
    for (int i = 0; i < 2 * pp->m; ++i) {
        p += element_to_bytes_(buf + p, ctxt->c2s[i]);
    }
    if ((res = net_send(fd, &length, sizeof length, 0)) == -1)
        goto cleanup;
    res = net_send(fd, buf, length, 0);
cleanup:
    free(buf);
    return res;
}

int
ase_ctxt_recv(const struct ase_pp_t *pp, struct ase_ctxt_t *ctxt, int fd)
{
    size_t length, p = 0;
    unsigned char *buf;
    int res = 0;

    if ((res = net_recv(fd, &length, sizeof length, 0)) == -1)
        return -1;
    if ((buf = malloc(length)) == NULL)
        return -1;
    if ((res = net_recv(fd, buf, length, 0)) == -1)
        goto cleanup;

    p += element_from_bytes_(ctxt->g, buf + p);
    p += element_from_bytes_(ctxt->h, buf + p);
    for (int i = 0; i < 2 * pp->m; ++i) {
        p += element_from_bytes_(ctxt->c2s[i], buf + p);
    }
cleanup:
    free(buf);
    return res;
    
}

/* Print ASE functions */

void
ase_pp_print(struct ase_pp_t *pp)
{
    printf("m = %d\n", pp->m);
}

void
ase_pk_print(struct ase_pp_t *pp, struct ase_pk_t *pk)
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
ase_sk_print(struct ase_pp_t *pp, struct ase_sk_t *sk)
{
    for (int i = 0; i < pp->m; ++i) {
        element_printf("rs[%d] = %B\n", i, sk->rs[i]);
    }
}


/* Main ASE functions */

void
ase_gen(struct ase_pp_t *pp, struct ase_master_t *msk,
         struct ase_pk_t *pk, struct ase_sk_t *sk, const int *attrs)
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
ase_vrfy(struct ase_pp_t *pp, struct ase_master_t *mpk, struct ase_pk_t *pk)
{
    element_t tmp;
    int res = 0;

    element_init_G1(tmp, pp->pairing);

    if (!bls_verify(&mpk->gsig, pk->gsig, pk->g, pp->pairing))
        goto cleanup;
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
ase_enc(struct ase_pp_t *pp, struct ase_pk_t *pk,
         struct ase_ctxt_t *ciphertext, element_t *plaintext,
         const unsigned int *seed)
{
    element_t s, t;
    element_pp_t g_pp, h_pp;

    element_init_Zr(s, pp->pairing);
    element_init_Zr(t, pp->pairing);
    element_pp_init(g_pp, pk->g);
    element_pp_init(h_pp, pk->h);

    if (seed) {
        pbc_random_set_deterministic(*seed);
    }

    element_random(s);
    element_random(t);
    element_pp_pow_zn(ciphertext->g, s, g_pp);
    element_pp_pow_zn(ciphertext->h, t, h_pp);

    for (int i = 0; i < pp->m; ++i) {
        element_pow_zn(ciphertext->c2s[2 * i], pk->es[i], s);
        element_mul(ciphertext->c2s[2 * i],
                    ciphertext->c2s[2 * i], plaintext[2 * i]);

        element_pow_zn(ciphertext->c2s[2 * i + 1], pk->es[i], t);
        element_mul(ciphertext->c2s[2 * i + 1],
                    ciphertext->c2s[2 * i + 1], plaintext[2 * i + 1]);
    }

    if (seed) {
        pbc_random_set_file("/dev/urandom");
    }

    element_clear(s);
    element_clear(t);
    element_pp_clear(g_pp);
    element_pp_clear(h_pp);
}

void
ase_enc_select(struct ase_pp_t *pp, struct ase_pk_t *pk, const int *attrs,
                struct ase_ctxt_t *ciphertext, element_t *plaintext,
                const unsigned int *seed)
{
    element_t s, t;
    element_pp_t g_pp, h_pp;

    element_init_Zr(s, pp->pairing);
    element_init_Zr(t, pp->pairing);
    element_pp_init(g_pp, pk->g);
    element_pp_init(h_pp, pk->h);

    if (seed) {
        pbc_random_set_deterministic(*seed);
    }

    element_random(s);
    element_random(t);
    element_pp_pow_zn(ciphertext->g, s, g_pp);
    element_pp_pow_zn(ciphertext->h, t, h_pp);

    for (int i = 0; i < pp->m; ++i) {
        if (attrs[i]) {
            element_pow_zn(ciphertext->c2s[2 * i + 1], pk->es[i], t);
            element_mul(ciphertext->c2s[2 * i + 1],
                        ciphertext->c2s[2 * i + 1], plaintext[2 * i + 1]);
        } else {
            element_pow_zn(ciphertext->c2s[2 * i], pk->es[i], s);
            element_mul(ciphertext->c2s[2 * i],
                        ciphertext->c2s[2 * i], plaintext[2 * i]);
        }
    }

    if (seed) {
        pbc_random_set_file("/dev/urandom");
    }

    element_clear(s);
    element_clear(t);
    element_pp_clear(g_pp);
    element_pp_clear(h_pp);
}

void
ase_dec(struct ase_pp_t *pp, struct ase_sk_t *sk, element_t *plaintext,
         struct ase_ctxt_t *ciphertext, const int *attrs)
{
    element_pp_t g_pp, h_pp;

    element_pp_init(g_pp, ciphertext->g);
    element_pp_init(h_pp, ciphertext->h);

    
    for (int i = 0; i < pp->m; ++i) {
        if (attrs[i]) {
            element_pp_pow_zn(plaintext[i], sk->rs[i], h_pp);
        } else {
            element_pp_pow_zn(plaintext[i], sk->rs[i], g_pp);
        }
        element_div(plaintext[i], ciphertext->c2s[2 * i + attrs[i]], plaintext[i]);
    }

    element_pp_clear(g_pp);
    element_pp_clear(h_pp);
}

void
ase_unlink(struct ase_pp_t *pp, struct ase_pk_t *rpk, struct ase_sk_t *rsk,
            struct ase_pk_t *pk, struct ase_sk_t *sk)
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
        element_set(rsk->rs[i], sk->rs[i]);
    }

    element_clear(r);
}
