#ifndef SERVER_H
#define SERVER_H

#include "ase.h"

int
server_go(const char *host, const char *port, int m, const char *param,
          enum ase_type_e type);

#endif
