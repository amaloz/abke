#include "ase.h"
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
    enum ase_type_e type;
    int m;
    char *host;
    char *port;
    int *attrs;
    char *param;
    char *policy;
};

static void
args_init(struct args *args)
{
    args->type = ASE_HOMOSIG;
    args->role = ROLE_NONE;
    args->m = 2;
    args->host = "127.0.0.1";
    args->port = "1250";
    args->attrs = NULL;
    args->param = "params/d224.param";
    args->policy = NULL;
}

static struct option opts[] = {
    {"ca", no_argument, 0, 'a'},
    {"server", no_argument, 0, 's'},
    {"client", no_argument, 0, 'c'},
    {"nattrs", required_argument, 0, 'm'},
    {"param", required_argument, 0, 'p'},
    {"policy", required_argument, 0, 'P'},
    {"test", no_argument, 0, 't'},
    {0, 0, 0, 0}
};

static char *short_opts = "acm:p:st";

static int
go(struct args *args)
{
    switch (args->role) {
    case ROLE_CA:
        ca_init(CA_HOST, CA_PORT, args->m, args->param, args->type);
        break;
    case ROLE_SERVER:
        server_go(args->host, args->port, args->m, args->param, args->type);
        break;
    case ROLE_CLIENT:
        client_go(args->host, args->port, args->attrs, args->m, args->param,
                  args->type);
        break;
    default:
        break;
    }
    return 0;
}

static int
testall(struct args *args)
{
    test_AND_circuit(args->attrs, args->m);
    test_ase();
    return 0;
}

static int
usage(void)
{
    /* TODO: write usage */
    return EXIT_FAILURE;
}

int
main(int argc, char *argv[])
{
    int c, idx, res, test = 0;
    struct args args;

    args_init(&args);

    while ((c = getopt_long(argc, argv, short_opts, opts, &idx)) != -1) {
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
        case 'p':
            args.param = optarg;
            break;
        case 'P':
            args.policy = optarg;
            break;
        case 's':
            args.role = ROLE_SERVER;
            break;
        case 't':
            test = 1;
            break;
        default:
            break;
        }
    }

    if (args.role == ROLE_NONE) {
        printf("Error: No role specified\n");
        return usage();
    }

    args.attrs = calloc(args.m, sizeof(int));
    for (int i = 0; i < args.m; ++i)
        args.attrs[i] = 1 /* rand() % 2 */;

    if (test)
        res = testall(&args);
    else
        res = go(&args);

    free(args.attrs);
    return res;
}
