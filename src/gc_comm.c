#include "gc_comm.h"
#include "net.h"

int
gc_comm_send(int sock, ExtGarbledCircuit *egc)
{
    char *buf;
    size_t size;
    int res = 0;

    size = gc_size(&egc->gc);
    if ((buf = malloc(size)) == NULL)
        return -1;
    gc2buf(&egc->gc, buf, false);
    if ((res = net_send(sock, &size, sizeof size, 0)) == -1)
        goto cleanup;
    res = net_send(sock, buf, size, 0);
    net_send(sock, egc->translations, 2 * egc->gc.n * sizeof(translation_t), 0);
cleanup:
    free(buf);
    return res;
}

int
gc_comm_recv(int sock, ExtGarbledCircuit *egc)
{
    size_t size;
    char *buf;
    int res = 0;

    if (net_recv(sock, &size, sizeof size, 0) == -1)
        return -1;
    if ((buf = malloc(size)) == NULL)
        return -1;
    if ((res = net_recv(sock, buf, size, 0)) == -1)
        goto cleanup;
    res = buf2gc(&egc->gc, buf, false);
    egc->translations = calloc(2 * egc->gc.n, sizeof(translation_t));
    net_recv(sock, egc->translations, 2 * egc->gc.n * sizeof(translation_t), 0);

cleanup:
    free(buf);
    return res;
}
