#ifndef ABKE_PARTY_H
#define ABKE_PARTY_H

#include "ase.h"
#include "util.h"

struct measurement_t {
    abke_time_t comp;
    abke_time_t ocomp;
    abke_time_t comm;
    size_t bytes_sent;
    size_t bytes_rcvd;
};

enum role_e { ROLE_SERVER, ROLE_CLIENT, ROLE_CA, ROLE_NONE };

int
ca_info(struct ase_pp_t *pp, struct ase_master_t *mpk, enum role_e role,
        struct ase_pk_t *pk, struct ase_sk_t *sk, const int *attrs,
        enum ase_type_e type);

int
ca_init(const char *host, const char *port, int m, int ntimes,
        enum ase_type_e type);

int
client_go(const char *host, const char *port, const int *attrs, int m,
          int q, struct measurement_t *measurements, enum ase_type_e type);
int
server_go(const char *host, const char *port, int m, int q,
          struct measurement_t *measurements, enum ase_type_e type);


#endif
