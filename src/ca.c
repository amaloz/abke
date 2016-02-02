#include "ca.h"

#include "net.h"
#include "util.h"

#include "justGarble.h"
#include <stdio.h>
#include <unistd.h>
#include <openssl/rand.h>

static int
loop(int sockfd, struct apse_pp_t *pp, struct apse_master_t *master)
{
    int fd;
    enum role_e role;

    if ((fd = net_server_accept(sockfd)) == -1) {
        perror("net_server_accept");
        return -1;
    }

    fprintf(stderr, "Connection from... ");

    net_recv(fd, &role, sizeof role, 0);
    switch (role) {
    case ROLE_CLIENT:
        fprintf(stderr, "CLIENT\n");
        break;
    case ROLE_SERVER:
        fprintf(stderr, "SERVER\n");
        break;
    default:
        fprintf(stderr, "INVALID!\n");
        return -1;
    }
    
    apse_mpk_send(pp, master, fd);
    if (role == ROLE_CLIENT) {
        int *attrs;
        struct apse_pk_t pk;
        struct apse_sk_t sk;

        attrs = calloc(pp->m, sizeof(int));
        apse_pk_init(pp, &pk);
        apse_sk_init(pp, &sk);
        net_recv(fd, attrs, sizeof(int) * pp->m, 0);
        apse_gen(pp, master, &pk, &sk, attrs);
        apse_pk_send(pp, &pk, fd);
        apse_sk_send(pp, &sk, fd);

        apse_sk_clear(pp, &sk);
        apse_pk_clear(pp, &pk);
        free(attrs);
    }
    close(fd);

    return 0;
}

int
ca_info(struct apse_pp_t *pp, struct apse_master_t *mpk, enum role_e role,
        struct apse_pk_t *pk, struct apse_sk_t *sk, const int *attrs)
{
    int cafd;

    if ((cafd = net_init_client(CA_HOST, CA_PORT)) == -1) {
        perror("net_init_client");
        return -1;
    }

    net_send(cafd, &role, sizeof role, 0);
    apse_mpk_recv(pp, mpk, cafd);
    if (role == ROLE_CLIENT) {
        net_send(cafd, attrs, sizeof(int) * pp->m, 0);
        apse_pk_recv(pp, pk, cafd);
        apse_sk_recv(pp, sk, cafd);
    }
    close(cafd);
    return 0;
}

int
ca_init(const char *host, const char *port, int m, const char *param)
{
    int sockfd;
    struct apse_master_t master;
    struct apse_pp_t pp;
    block seed;

    fprintf(stderr, "Starting CA with m = %d and pairing %s\n", m, param);
    
    if ((sockfd = net_init_server(host, port)) == -1) {
        perror("net_init_server");
        return -1;
    }

    (void) RAND_bytes((unsigned char *) &seed, sizeof seed);
    (void) seedRandom(&seed);

    if (apse_pp_init(&pp, m, param))
        return -1;
    apse_master_init(&pp, &master);

    while (1) {
        if (loop(sockfd, &pp, &master) == -1)
            return -1;
    }

    apse_master_clear(&pp, &master);
    apse_pp_clear(&pp);

    return 0;
}
