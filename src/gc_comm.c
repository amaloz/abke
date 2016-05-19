#include "gc_comm.h"
#include "net.h"

int
gc_comm_send(FILE *f, ExtGarbledCircuit *egc)
{
    char *buf;
    size_t size;
    int res = 0;

    size = garble_size(&egc->gc, false);
    if ((buf = malloc(size)) == NULL)
        return -1;
    garble_to_buffer(&egc->gc, buf, false);
    net_send(f, &size, sizeof size);
    net_send(f, buf, size);
    net_send(f, egc->ttables, 2 * egc->gc.n * sizeof(block));

    free(buf);
    return res;
}

int
gc_comm_recv(FILE *f, ExtGarbledCircuit *egc)
{
    size_t size;
    char *buf;
    int res = 0;

    net_recv(f, &size, sizeof size);
    if ((buf = malloc(size)) == NULL)
        return -1;
    net_recv(f, buf, size);
    res = garble_from_buffer(&egc->gc, buf, false);
    egc->ttables = calloc(2 * egc->gc.n, sizeof(block));
    net_recv(f, egc->ttables, 2 * egc->gc.n * sizeof(block));

    free(buf);
    return res;
}
