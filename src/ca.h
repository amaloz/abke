#ifndef CA_H
#define CA_H

#include "apse.h"

int
ca_info(struct apse_pp_t *pp, struct apse_master_t *mpk, struct apse_pk_t *pk,
        struct apse_sk_t *sk, const int *attrs);
int
ca_init(const char *host, const char *port, int m, const char *fname);

#endif
