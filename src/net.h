#ifndef __NET_H
#define __NET_H

#include <netinet/in.h>
#include <pbc/pbc.h>

#define BACKLOG 5

int
net_send_element(int socket, element_t elem);
int
net_recv_element(int socket, element_t elem);

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
