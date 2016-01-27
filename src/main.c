#include "ca.h"
#include "client.h"
#include "server.h"
#include "util.h"

#include "justGarble.h"
#include <getopt.h>
#include <stdio.h>

enum role_e { ROLE_SERVER, ROLE_CLIENT, ROLE_CA, ROLE_NONE };

struct args {
    enum role_e role;
    int m;
    char *host;
    char *port;
    int *attrs;
};

static void
args_init(struct args *args)
{
    args->role = ROLE_NONE;
    args->m = 2;
    args->host = "127.0.0.1";
    args->port = "1250";
    args->attrs = calloc(args->m, sizeof(int));
    for (int i = 0; i < args->m; ++i)
        args->attrs[i] = 0;
}

static struct option opts[] = {
    {"ca", no_argument, 0, 'a'},
    {"server", no_argument, 0, 's'},
    {"client", no_argument, 0, 'c'},
    {0, 0, 0, 0}
};


static int
go(struct args *args)
{
    switch (args->role) {
    case ROLE_CA:
        ca_init(CA_HOST, CA_PORT, args->m, PARAMFILE);
        break;
    case ROLE_SERVER:
        server_go(args->host, args->port, args->attrs, args->m);
        break;
    case ROLE_CLIENT:
        client_go(args->host, args->port, args->attrs, args->m);
        break;
    default:
        break;
    }
    return 0;
}

int
main(int argc, char *argv[])
{
    int c, idx;
    struct args args;

    args_init(&args);

    while ((c = getopt_long(argc, argv, "acs", opts, &idx)) != -1) {
        switch (c) {
        case 'a':
            args.role = ROLE_CA;
            break;
        case 'c':
            args.role = ROLE_CLIENT;
            break;
        case 's':
            args.role = ROLE_SERVER;
            break;
        default:
            break;
        }
    }
    return go(&args);
}
