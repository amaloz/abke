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

/* static int */
/* test_apse(void) */
/* { */
/*     struct apse_pp_t pp; */
/*     struct apse_master_t master; */
/*     struct apse_pk_t pk; */
/*     struct apse_sk_t sk; */
/*     int *attrs; */
/*     struct apse_ctxt_elem_t *ctxt; */
/*     element_t *inputs; */
/*     element_t *ptxt; */

/*     apse_pp_init(&pp, 1, PARAMFILE, NULL); */
/*     apse_master_init(&pp, &master); */
/*     apse_pk_init(&pp, &pk); */
/*     apse_sk_init(&pp, &sk); */
/*     attrs = calloc(pp.m, sizeof(int)); */
/*     ptxt = calloc(pp.m, sizeof(element_t)); */
/*     for (int i = 0; i < pp.m; ++i) { */
/*         attrs[i] = 0; */
/*         element_init_G1(ptxt[i], pp.pairing); */
        
/*     } */
/*     inputs = calloc(2 * pp.m, sizeof(element_t)); */
/*     ctxt = calloc(2 * pp.m, sizeof(struct apse_ctxt_elem_t)); */
/*     for (int i = 0; i < 2 * pp.m; ++i) { */
/*         element_init_G1(inputs[i], pp.pairing); */
/*         element_random(inputs[i]); */
/*         element_init_G1(ctxt[i].ca, pp.pairing); */
/*         element_init_G1(ctxt[i].cb, pp.pairing); */
/*     } */

/*     apse_gen(&pp, &master, &pk, &sk, attrs); */
/*     apse_enc(&pp, &pk, ctxt, inputs, NULL); */
/*     apse_dec(&pp, &sk, ptxt, ctxt, attrs); */
/*     for (int i = 0; i < pp.m; ++i) { */
/*         element_printf("%B\n%B\n%B\n\n", inputs[2 * i], inputs[2 * i + 1], ptxt[i]); */
/*     } */

/*     return 0; */
/* } */

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
