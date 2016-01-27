#include "apse.h"
#include "ca.h"
#include "gc_comm.h"
#include "net.h"
#include "util.h"

#include <assert.h>
#include <unistd.h>

int
client_go(const char *host, const char *port, const int *attrs, int m)
{
    int fd;
    struct apse_pp_t pp;
    struct apse_master_t mpk;
    struct apse_pk_t pk, rpk;
    struct apse_sk_t sk, rsk;
    struct apse_ctxt_elem_t *ctxt;
    GarbledCircuit gc;
    block *ilabels;
    block olabel, hash, seed;

    apse_pp_init(&pp, m, PARAMFILE, NULL);
    apse_master_init(&pp, &mpk);
    apse_pk_init(&pp, &pk);
    apse_sk_init(&pp, &sk);
    apse_pk_init(&pp, &rpk);
    apse_sk_init(&pp, &rsk);

    if (ca_info(&pp, &mpk, &pk, &sk, attrs) == -1) {
        fprintf(stderr, "Unable to connect to CA\n");
        return -1;
    }

    ctxt = calloc(2 * pp.m, sizeof(struct apse_ctxt_elem_t));
    for (int i = 0; i < 2 * pp.m; ++i) {
        element_init_G1(ctxt[i].ca, pp.pairing);
        element_init_G1(ctxt[i].cb, pp.pairing);
    }
    ilabels = allocate_blocks(pp.m);

    if ((fd = net_init_client(host, port)) == -1) {
        perror("net_init_client");
        return -1;
    }

    apse_unlink(&pp, &rpk, &rsk, &pk, &sk);
    apse_pk_send(&pp, &rpk, fd);
    for (int i = 0; i < 2 * pp.m; ++i) {
        net_recv_element(fd, ctxt[i].ca);
        net_recv_element(fd, ctxt[i].cb);
    }
    gc_comm_recv(fd, &gc);
    apse_dec(&pp, &sk, ilabels, ctxt, attrs);
    evaluate(&gc, ilabels, &olabel, GARBLE_TYPE_STANDARD);
    hash = hash_block(olabel);
    net_send(fd, &hash, sizeof hash, 0);
    net_recv(fd, &seed, sizeof seed, 0);
    /* XXX: also receive randomness used for computing enc */

    /* TODO: finish */
    
    apse_sk_clear(&pp, &rsk);
    apse_pk_clear(&pp, &rpk);
    apse_sk_clear(&pp, &sk);
    apse_pk_clear(&pp, &pk);
    apse_master_clear(&pp, &mpk);
    apse_pp_clear(&pp);

    close(fd);

    return 0;
}
