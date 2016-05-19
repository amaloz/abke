#ifndef __NET_H
#define __NET_H

#include <netinet/in.h>
#include <stdio.h>

extern int g_bytes_sent, g_bytes_rcvd;

int
net_send(FILE *f, const void *buffer, size_t length);

int
net_recv(FILE *f, void *buffer, size_t length);

void *
net_get_in_addr(struct sockaddr *sa);

int
net_init_server(const char *addr, const char *port);

int
net_server_accept(int sockfd);

int
net_init_client(const char *addr, const char *port);


#endif
