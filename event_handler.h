#ifndef __EVENT_HANDLER_H__
#define __EVENT_HANDLER_H__

#include "connection.h"

void tcp_accept_from_frontend(int fd, short events, void *data);

void ssl_accept_from_frontend(int fd, short events, void *data);

void tcp_connect_to_backend(int fd, short events, void *data);

void ssl_read_from_frontend(int fd, short events, void *data);

void tcp_send_to_backend(int fd, short events, void *data);

void tcp_recv_from_backend(int fd, short events, void *data);

void ssl_write_to_frontend(int fd, short events, void *data);

void tcp_conn_free(connection_t *conn);

#endif
