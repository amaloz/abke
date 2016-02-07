#include "ase.h"
#include "party.h"
#include "policies.h"
#include "test.h"
#include "util.h"

#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <unistd.h>

struct args {
    enum role_e role;
    enum ase_type_e type;
    int m;
    int ngates;
    int ntimes;
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
    args->ngates = args->m - 1;
    args->ntimes = 1;
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
    {"ngates", required_argument, 0, 'q'},
    {"ntimes", required_argument, 0, 't'},
    {"test", no_argument, 0, 'T'},
    {0, 0, 0, 0}
};
static char *short_opts = "acm:p:q:st:T";

static int
compare(const void * a, const void * b)
{
	return (*(abke_time_t *) a - *(abke_time_t *) b);
}

static abke_time_t
mymedian(abke_time_t *values, int n)
{
	qsort(values, n, sizeof(mytime_t), compare);
    if (n == 0)
        return 0;
    else if (n == 1)
        return values[0];
    else if (n % 2 == 1)
		return values[(n + 1) / 2 - 1];
	else
		return (values[n / 2 - 1] + values[n / 2]) / 2;
}


static int
go(struct args *args)
{
    if (args->role == ROLE_CA) {
        ca_init(CA_HOST, CA_PORT, args->m, args->ntimes, args->param, args->type);
    } else {
        struct measurement_t measurements;
        abke_time_t *comps = calloc(args->ntimes, sizeof(abke_time_t));
        abke_time_t *comms = calloc(args->ntimes, sizeof(abke_time_t));
        size_t *bytes_sent = calloc(args->ntimes, sizeof(size_t));
        size_t *bytes_rcvd = calloc(args->ntimes, sizeof(size_t));
        double *compMedians = calloc(args->ntimes, sizeof(double));
        double *commMedians = calloc(args->ntimes, sizeof(double));
        double meanComp, meanComm;

        if (args->ngates < args->m - 1)
            args->ngates = args->m - 1;

        for (int i = 0; i < args->ntimes; ++i) {
            for (int j = 0; j < args->ntimes; ++j) {
                switch (args->role) {
                case ROLE_SERVER:
                    server_go(args->host, args->port, args->m, args->ngates,
                              args->param, &measurements, args->type);
                    break;
                case ROLE_CLIENT:
                    client_go(args->host, args->port, args->attrs, args->m,
                              args->ngates, args->param, &measurements,
                              args->type);
                    sleep(1);
                    break;
                default:
                    assert(0);
                    abort();
                }
                comps[j] = measurements.comp;
                comms[j] = measurements.comm;
            }
            compMedians[i] = (double) mymedian(comps, args->ntimes);
            commMedians[i] = (double) mymedian(comms, args->ntimes);
        }
        fprintf(stderr, "\n");
        {
            GarbledCircuit gc;
            build_AND_policy(&gc, args->m, args->ngates);
            fprintf(stderr, "%d %d\n", gc.n, gc.q);
            removeGarbledCircuit(&gc);
        }
        meanComp = doubleMean(compMedians, args->ntimes);
        meanComm = doubleMean(commMedians, args->ntimes);
        switch (args->role) {
        case ROLE_SERVER:
            printf("Server: %lf %lf\n", meanComp, meanComm);
            break;
        case ROLE_CLIENT:
            printf("Client: %lf %lf\n", meanComp, meanComm);
            break;
        default:
            assert(0);
            abort();
        }

        free(comps);
        free(comms);
        free(bytes_sent);
        free(bytes_rcvd);
    }

    return 0;
}

static int
testall(struct args *args)
{
    test_AND_circuit(args->attrs, args->m, args->ngates);
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
        case 'q':
            args.ngates = atoi(optarg);
            break;
        case 's':
            args.role = ROLE_SERVER;
            break;
        case 't':
            args.ntimes = atoi(optarg);
            break;
        case 'T':
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
