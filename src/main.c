#include "ca.h"
#include "client.h"
#include "server.h"
#include "test.h"
#include "util.h"

#include "justGarble.h"
#include <getopt.h>
#include <stdio.h>

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
    args->m = 16;
    args->host = "127.0.0.1";
    args->port = "1250";
    args->attrs = NULL;
}

static struct option opts[] = {
    {"ca", no_argument, 0, 'a'},
    {"server", no_argument, 0, 's'},
    {"client", no_argument, 0, 'c'},
    {"nattrs", required_argument, 0, 'm'},
    {"test", no_argument, 0, 't'},
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
        server_go(args->host, args->port, args->m);
        break;
    case ROLE_CLIENT:
        client_go(args->host, args->port, args->attrs, args->m);
        break;
    default:
        break;
    }
    return 0;
}

static int
test(struct args *args)
{
    test_AND_circuit(args->m);
    /* test_apse(); */
    return 0;
}

int
main(int argc, char *argv[])
{
    int c, idx, res;
    struct args args;

    args_init(&args);

    while ((c = getopt_long(argc, argv, "acm:st", opts, &idx)) != -1) {
        switch (c) {
        case 'a':
            args.role = ROLE_CA;
            break;
        case 'c':
            args.role = ROLE_CLIENT;
            break;
        case 'm':
            args.m = atoi(optarg);
            break;
        case 's':
            args.role = ROLE_SERVER;
            break;
        case 't':
            return test(&args);
        default:
            break;
        }
    }
    args.attrs = calloc(args.m, sizeof(int));
    for (int i = 0; i < args.m; ++i)
        args.attrs[i] = 1 /* rand() % 2 */;
    res = go(&args);
    free(args.attrs);
    return res;
}
