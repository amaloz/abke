#include "apse.h"
#include "net.h"
#include "util.h"

#include "justGarble.h"
#include <stdio.h>
#include <unistd.h>

static int
loop(int sockfd, struct apse_pp_t *pp, struct apse_master_t *master)
{
    int fd;
    int *attrs;
    struct apse_pk_t pk;
    struct apse_sk_t sk;

    if ((fd = net_server_accept(sockfd)) == -1) {
        perror("net_server_accept");
        return -1;
    }

    fprintf(stderr, "Connection...\n");

    attrs = calloc(pp->m, sizeof(int));
    apse_pk_init(pp, &pk);
    apse_sk_init(pp, &sk);

    apse_mpk_send(pp, master, fd);
    net_recv(fd, attrs, sizeof(int) * pp->m, 0);
    apse_gen(pp, master, &pk, &sk, attrs);
    apse_pk_send(pp, &pk, fd);
    apse_sk_send(pp, &sk, fd);

    apse_sk_clear(pp, &sk);
    apse_pk_clear(pp, &pk);
    free(attrs);

    close(fd);

    return 0;
}

int
ca_info(struct apse_pp_t *pp, struct apse_master_t *mpk, struct apse_pk_t *pk,
        struct apse_sk_t *sk, const int *attrs)
{
    int cafd;
    /* struct apse_pk_t lpk; */
    /* struct apse_sk_t lsk; */
    /* int delete_pk = 0, delete_sk = 0; */


    /* if (!pk) { */
    /*     apse_pk_init(pp, &lpk); */
    /*     pk = &lpk; */
    /*     delete_pk = 1; */
    /* } */
    /* if (!sk) { */
    /*     apse_sk_init(pp, &lsk); */
    /*     sk = &lsk; */
    /*     delete_sk = 1; */
    /* } */

    if ((cafd = net_init_client(CA_HOST, CA_PORT)) == -1) {
        perror("net_init_client");
        return -1;
    }

    apse_mpk_recv(pp, mpk, cafd);
    net_send(cafd, attrs, sizeof(int) * pp->m, 0);
    apse_pk_recv(pp, pk, cafd);
    apse_sk_recv(pp, sk, cafd);

    /* if (delete_pk) */
    /*     apse_pk_clear(pp, &lpk); */
    /* if (delete_sk) */
    /*     apse_sk_clear(pp, &lsk); */

    close(cafd);
    return 0;
}

int
ca_init(const char *host, const char *port, int m, const char *fname)
{
    int sockfd;
    struct apse_master_t master;
    struct apse_pp_t pp;
    
    if ((sockfd = net_init_server(host, port)) == -1) {
        perror("net_init_server");
        return -1;
    }

    (void) seedRandom(NULL);

    apse_pp_init(&pp, m, fname, NULL);
    apse_master_init(&pp, &master);

    while (1) {
        if (loop(sockfd, &pp, &master) == -1)
            return -1;
    }

    apse_master_clear(&pp, &master);
    apse_pp_clear(&pp);

    return 0;
}
