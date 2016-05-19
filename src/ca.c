#include "party.h"

#include "net.h"
#include "util.h"

#include <garble.h>

#include <stdio.h>
#include <unistd.h>
#include <openssl/rand.h>

static int
loop(int sockfd, struct ase_pp_t *pp, struct ase_master_t *master,
     enum ase_type_e type)
{
    int fd = -1;
    FILE *f = NULL;
    enum role_e role;

    if ((fd = net_server_accept(sockfd)) == -1) {
        perror("net_server_accept");
        return -1;
    }
    if ((f = fdopen(fd, "wb+")) == NULL) {
        perror("fdopen");
        close(fd);
        return -1;
    }

    fprintf(stderr, "Connection from... ");

    net_recv(f, &role, sizeof role);
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
    
    ase_mpk_send(pp, master, f, type);
    if (role == ROLE_CLIENT) {
        int *attrs;
        struct ase_pk_t pk;
        struct ase_sk_t sk;

        attrs = calloc(pp->m, sizeof(int));
        ase_pk_init(pp, &pk, type);
        ase_sk_init(pp, &sk, type);
        net_recv(f, attrs, sizeof(int) * pp->m);
        ase_gen(pp, master, &pk, &sk, attrs, type);
        ase_pk_send(pp, &pk, f, type);
        ase_sk_send(pp, &sk, f, type);

        ase_sk_clear(pp, &sk, type);
        ase_pk_clear(pp, &pk, type);
        free(attrs);
    }
    fclose(f);
    close(fd);

    return 0;
}

int
ca_info(struct ase_pp_t *pp, struct ase_master_t *mpk, enum role_e role,
        struct ase_pk_t *pk, struct ase_sk_t *sk, const int *attrs,
        enum ase_type_e type)
{
    int cafd;
    FILE *f = NULL;

    if ((cafd = net_init_client(CA_HOST, CA_PORT)) == -1) {
        perror("net_init_client");
        return -1;
    }
    if ((f = fdopen(cafd, "wb+")) == NULL) {
        perror("fdopen");
        close(cafd);
        return -1;
    }

    net_send(f, &role, sizeof role);
    ase_mpk_recv(pp, mpk, f, type);
    if (role == ROLE_CLIENT) {
        net_send(f, attrs, sizeof(int) * pp->m);
        ase_pk_recv(pp, pk, f, type);
        ase_sk_recv(pp, sk, f, type);
    }
    fclose(f);
    close(cafd);
    return 0;
}

int
ca_init(const char *host, const char *port, int m, int ntimes,
        const char *param, enum ase_type_e type)
{
    int sockfd;
    struct ase_master_t master;
    struct ase_pp_t pp;
    block seed;
    int nconnected = 0;

    fprintf(stderr, "Starting CA with m = %d and pairing %s\n", m, param);
    
    if ((sockfd = net_init_server(host, port)) == -1) {
        perror("net_init_server");
        return -1;
    }

    (void) RAND_bytes((unsigned char *) &seed, sizeof seed);
    (void) garble_seed(&seed);

    if (ase_pp_init(&pp, m, param))
        return -1;
    ase_master_init(&pp, &master, type);

    while (nconnected < 2 * ntimes * ntimes) {
        if (loop(sockfd, &pp, &master, type) == -1)
            return -1;
        nconnected++;
    }

    ase_master_clear(&pp, &master, type);
    ase_pp_clear(&pp);

    return 0;
}
