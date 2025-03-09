#ifndef SOCKET_THREAD_H
#define SOCKET_THREAD_H

#include <stdbool.h>
#include "queue.h"
#define BUFFER_SIZE 1024

typedef struct socket_thread
{
    bool completed;
    char *buffer;
    int client_sockfd;
    char *ip_address_str;
    pthread_t sthread;
} socket_thread_t;

typedef struct slist_data_s
{
    socket_thread_t *value;
    SLIST_ENTRY(slist_data_s)
    entries;
} slist_socket_t;

socket_thread_t *init_socket()
{
    socket_thread_t *returned = malloc(sizeof(socket_thread_t));
    *returned = (socket_thread_t){false, calloc(BUFFER_SIZE, 1), -1};
    return returned;
}

#endif /* !SOCKET_THREAD_H */