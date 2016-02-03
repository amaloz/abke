#ifndef CLIENT_H
#define CLIENT_H

#include "ase.h"

int
client_go(const char *host, const char *port, const int *attrs, int m,
          const char *param, enum ase_type_e type);

#endif
