#ifndef __NET_H
#define __NET_H

#include <netinet/in.h>
#include <pbc/pbc.h>

extern int g_bytes_sent, g_bytes_rcvd;

int
net_send(int socket, const void *buffer, size_t length, int flags);

int
net_recv(int socket, void *buffer, size_t length, int flags);

void *
net_get_in_addr(struct sockaddr *sa);

int
net_init_server(const char *addr, const char *port);

int
net_server_accept(int sockfd);

int
net_init_client(const char *addr, const char *port);


#endif
