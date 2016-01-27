#include "apse.h"
#include "ca.h"
#include "gc_comm.h"
#include "net.h"
#include "util.h"

#include <assert.h>
#include <unistd.h>
#include "garble.h"
#include "gates.h"

static void
buildCircuit(GarbledCircuit *gc, int n, int nlayers)
{
    block inputLabels[2 * n];
    block outputLabels[n];
    GarblingContext ctxt;
    int wire;
    int wires[n];
    int r = n + n / 2 * nlayers;
    int q = n / 2 * nlayers;

    countToN(wires, n);

    createInputLabels(inputLabels, n);
    createEmptyGarbledCircuit(gc, n, n, q, r, inputLabels);
    startBuilding(gc, &ctxt);

    for (int i = 0; i < nlayers; ++i) {
        for (int j = 0; j < n; j += 2) {
            wire = getNextWire(&ctxt);
            ANDGate(gc, &ctxt, wires[j], wires[j+1], wire);
            wires[j] = wires[j+1] = wire;
        }
    }

    finishBuilding(gc, &ctxt, outputLabels, wires);
}

int
server_go(const char *host, const char *port, const int *attrs, int m)
{
    int sockfd, fd;
    block seed, hash;
    struct apse_pp_t pp;
    struct apse_master_t mpk;
    struct apse_pk_t pk, client_pk;
    struct apse_sk_t sk;
    struct apse_ctxt_elem_t *ctxt;
    GarbledCircuit gc;

    apse_pp_init(&pp, m, PARAMFILE, NULL);
    apse_master_init(&pp, &mpk);
    apse_pk_init(&pp, &pk);
    apse_sk_init(&pp, &sk);
    
    if (ca_info(&pp, &mpk, &pk, &sk, attrs) == -1) {
        fprintf(stderr, "Unable to connect to CA\n");
        return -1;
    }

    ctxt = calloc(2 * pp.m, sizeof(struct apse_ctxt_elem_t));
    for (int i = 0; i < 2 * pp.m; ++i) {
        element_init_G1(ctxt[i].ca, pp.pairing);
        element_init_G1(ctxt[i].cb, pp.pairing);
    }

    seed = seedRandom(NULL);
    buildCircuit(&gc, pp.m, 1);
    garbleCircuit(&gc, NULL, GARBLE_TYPE_STANDARD);
    assert(pp.m == gc.n);

    if ((sockfd = net_init_server(host, port)) == -1) {
        perror("net_init_server");
        exit(EXIT_FAILURE);
    }
    if ((fd = net_server_accept(sockfd)) == -1) {
        perror("net_server_accept");
        exit(EXIT_FAILURE);
    }

    apse_pk_init(&pp, &client_pk);

    /* Get randomized pk from client */
    apse_pk_recv(&pp, &client_pk, fd);
    if (apse_vrfy(&pp, &mpk, &client_pk) == 0) {
        fprintf(stderr, "pk fails to verify\n");
        goto cleanup;
    }
    fprintf(stderr, "client pk verifies!\n");

    apse_enc(&pp, &pk, ctxt, (block *) &gc.wires[0]);
    for (int i = 0; i < 2 * pp.m; ++i) {
        net_send_element(fd, ctxt[i].ca);
        net_send_element(fd, ctxt[i].cb);
    }
    gc_comm_send(fd, &gc);
    
    net_recv(fd, &hash, sizeof hash, 0);
    net_send(fd, &seed, sizeof seed, 0);
    /* XXX: also send randomness used for computing enc */
    {
        block hash2;
        net_recv(fd, &hash2, sizeof hash2, 0);
        hash2 = hash_block(hash2);
        /* TODO: check equality */
    }


cleanup:
    for (int i = 0; i < 2 * m; ++i) {
        element_clear(ctxt[i].ca);
        element_clear(ctxt[i].cb);
    }
    free(ctxt);
    apse_pk_clear(&pp, &client_pk);

    apse_sk_clear(&pp, &sk);
    apse_pk_clear(&pp, &pk);
    apse_master_clear(&pp, &mpk);
    apse_pp_clear(&pp);

    close(fd);
    close(sockfd);

    return 0;
}
