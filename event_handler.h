#ifndef __EVENT_HANDLER_H__
#define __EVENT_HANDLER_H__

#include "worker.h"
#include "connection.h"

#define MAX_DATA_SIZE 65536

void on_timer(int fd, short events, void *data);

void on_signal(int fd, short events, void *data);

void tcp_accept_from_frontend(int fd, short events, void *data);

void ssl_accept_from_frontend(int fd, short events, void *data);

void ssl_read_from_frontend(int fd, short events, void *data);

void tcp_recv_from_backend(int fd, short events, void *data);

void event_conn_free(worker_t *work, connection_t *conn);

#endif
