#ifndef CA_H
#define CA_H

#include "apse.h"

enum role_e { ROLE_SERVER, ROLE_CLIENT, ROLE_CA, ROLE_NONE };

int
ca_info(struct apse_pp_t *pp, struct apse_master_t *mpk, enum role_e role,
        struct apse_pk_t *pk, struct apse_sk_t *sk, const int *attrs);

int
ca_init(const char *host, const char *port, int m, const char *fname);

#endif
