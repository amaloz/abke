#include "ase.h"
#include "party.h"
#include "policies.h"
#include "util.h"

#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <time.h>
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
    {0, 0, 0, 0}
};
static char *short_opts = "acm:p:q:st:";

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
        struct timespec t1, t2;
        struct measurement_t measurements;
        abke_time_t *comps = calloc(args->ntimes, sizeof(abke_time_t));
        abke_time_t *ocomps = calloc(args->ntimes, sizeof(abke_time_t));
        abke_time_t *comms = calloc(args->ntimes, sizeof(abke_time_t));
        size_t bytes_sent = 0;
        size_t bytes_rcvd = 0;
        double *compMedians = calloc(args->ntimes, sizeof(double));
        double *ocompMedians = calloc(args->ntimes, sizeof(double));
        double *commMedians = calloc(args->ntimes, sizeof(double));
        double meanComp, meanOComp, meanComm;

        t1.tv_sec = 0;
        t1.tv_nsec = 100000000L;

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
                    nanosleep(&t1, &t2);
                    break;
                default:
                    assert(0);
                    abort();
                }
                if (bytes_sent == 0)
                    bytes_sent = measurements.bytes_sent;
                else
                    assert(bytes_sent == measurements.bytes_sent);
                if (bytes_rcvd == 0)
                    bytes_rcvd = measurements.bytes_rcvd;
                else
                    assert(bytes_rcvd == measurements.bytes_rcvd);
                comps[j] = measurements.comp;
                ocomps[j] = measurements.ocomp;
                comms[j] = measurements.comm;
            }
            compMedians[i] = (double) mymedian(comps, args->ntimes);
            ocompMedians[i] = (double) mymedian(ocomps, args->ntimes);
            commMedians[i] = (double) mymedian(comms, args->ntimes);
        }
        fprintf(stderr, "\n");
        {
            garble_circuit gc;
            build_AND_policy(&gc, args->m, args->ngates);
            garble_delete(&gc);
        }
        meanComp = doubleMean(compMedians, args->ntimes);
        meanOComp = doubleMean(ocompMedians, args->ntimes);
        meanComm = doubleMean(commMedians, args->ntimes);
        switch (args->role) {
        case ROLE_SERVER:
            printf("Server: %lf %lf %lf %zu\n", meanComp, meanOComp, meanComm,
                   bytes_sent);
            break;
        case ROLE_CLIENT:
            printf("Client: %lf %lf %lf %zu\n", meanComp, meanOComp, meanComm,
                   bytes_sent);
            break;
        default:
            assert(0);
            abort();
        }

        free(comps);
        free(comms);
    }

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
    int c, idx, res;
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
        default:
            break;
        }
    }

    args.attrs = calloc(args.m, sizeof(int));
    for (int i = 0; i < args.m; ++i)
        args.attrs[i] = 1 /* rand() % 2 */;

    if (args.role == ROLE_NONE) {
        printf("Error: No role specified\n");
        return usage();
    } else {
        res = go(&args);
    }

    free(args.attrs);
    return res;
}
