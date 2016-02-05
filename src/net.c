#include "net.h"
#include "util.h"

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#define BACKLOG 5

int g_bytes_sent = 0;
int g_bytes_rcvd = 0;

int
net_send(int socket, const void *buffer, size_t length, int flags)
{
    size_t total = 0;
    ssize_t bytesleft = length;

    while (total < length) {
        ssize_t n = send(socket, buffer + total, bytesleft, flags);
        if (n == -1) {
            perror("send");
            return -1;
        }
        total += n;
        bytesleft -= n;
    }
    g_bytes_sent += length;
    return 0;
}

int
net_recv(int socket, void *buffer, size_t length, int flags)
{
    size_t total = 0;
    ssize_t bytesleft = length;

    while (total < length) {
        ssize_t n = recv(socket, buffer + total, bytesleft, flags);
        if (n == -1) {
            perror("recv");
            return -1;
        }
        total += n;
        bytesleft -= n;
    }
    g_bytes_rcvd += length;
    return 0;
}

void *
net_get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
        return &(((struct sockaddr_in *) sa)->sin_addr);
    else
        return &(((struct sockaddr_in6 *) sa)->sin6_addr);
}

int
net_init_server(const char *addr, const char *port)
{
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int yes = 1;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((rv = getaddrinfo(addr, port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                sizeof(int)) == -1) {
            perror("setsockopt");
            return -1;
        }
        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }
        break;
    }

    if (p == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        return -1;
    }

    freeaddrinfo(servinfo);

    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        return -1;
    }

    return sockfd;
}

int
net_server_accept(int sockfd)
{
    struct sockaddr_storage their_addr;
    socklen_t addr_size = sizeof their_addr;

    return accept(sockfd, (struct sockaddr *) &their_addr, &addr_size);
}

int
net_init_client(const char *addr, const char *port)
{
    int sockfd, rv;
    struct addrinfo hints, *servinfo, *p;
    char s[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(addr, port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("client: socket");
            continue;
        }
        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("client: connect");
            continue;
        }
        break;
    }

    if (p == NULL) {
        freeaddrinfo(servinfo);
        return -1;
    }

    inet_ntop(p->ai_family, net_get_in_addr((struct sockaddr *) p->ai_addr),
              s, sizeof s);

    freeaddrinfo(servinfo);

    return sockfd;
}
