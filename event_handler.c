#include <event.h>
#include "log.h"
#include "tcp_utils.h"
#include "ssl_utils.h"
#include "worker.h"
#include "master.h"
#include "connection.h"
#include "timer_handler.h"
#include "event_handler.h"

void on_timer(int fd, short events, void *data)
{
    worker_t *work = (worker_t*)data;
    struct event *event = &work->ev_timer;
    struct timeval tv = 
    {
        .tv_sec = 1,
        .tv_usec = 0
    };
    evtimer_add(event, &tv);
    timer_beat(&work->timer, get_local_time());
}

void on_signal(int fd, short events, void *data)
{
    struct event *event = (struct event*)data;
    struct event_base *base = event->ev_base;
    struct timeval tv = 
    {
        .tv_sec = 1,
        .tv_usec = 0
    };
    event_base_loopexit(base, &tv);
}

void tcp_accept_from_frontend(int fd, short events, void *data)
{
    int ret = 0;
    int slot = 0;
    config_t *conf = NULL;

    SSL *ssl = NULL;
    int frontend_fd = 0;
    int backend_fd = 0;
    char frontend_ip[32+1] = {0};
    unsigned short frontend_port = 0;

    worker_t *work = (worker_t*)data;
    if(work == NULL)
        return;
    slot = work->conn[fd].slot;
    conf = &work->mast->conf;

    frontend_fd = tcp_accept(fd, frontend_ip, 32+1, &frontend_port);
    if(frontend_fd == -1)
    {
        if(errno != EAGAIN) log_err("%s tcp accept from frontend failed - %d: %s", conf->ctrl[slot].serverName, errno, strerror(errno));    //Epoll惊群
        return;
    }
    log_debug("%s tcp accept from frontend \"%s:%hu\" succeed", conf->ctrl[slot].serverName, frontend_ip, frontend_port);

    backend_fd = tcp_socket();
    if(backend_fd == -1)
    {
        log_err("%s tcp socket failed - %d: %s", conf->ctrl[slot].serverName, errno, strerror(errno));
        tcp_close(frontend_fd);
        return;
    }

    ret = tcp_connect(backend_fd, conf->addr[slot].backend_ip, conf->addr[slot].backend_port);
    if(ret == -1)
    {
        log_err("%s tcp connect to backend \"%s:%hu\" failed - %d: %s", conf->ctrl[slot].serverName, conf->addr[slot].backend_ip, conf->addr[slot].backend_port, errno, strerror(errno));
        tcp_close(frontend_fd);
        tcp_close(backend_fd);
        return;
    }
    log_debug("%s tcp connect to backend \"%s:%hu\" succeed", conf->ctrl[slot].serverName, conf->addr[slot].backend_ip, conf->addr[slot].backend_port);

    ssl = SSL_new(work->ctx[slot]);
    if(ssl == NULL)
        goto ErrP;
    SSL_set_fd(ssl, frontend_fd);

    //前端数据
    work->conn[frontend_fd].slot = slot;
    work->conn[frontend_fd].fd = frontend_fd;
    work->conn[frontend_fd].ssl = ssl;
    work->conn[frontend_fd].ip = strdup(frontend_ip);
    work->conn[frontend_fd].port = frontend_port;
    work->conn[frontend_fd].peer = &work->conn[backend_fd];                             //对端节点
    list_add_tail(&work->conn[frontend_fd].list, &work->list);

    event_assign(&work->conn[frontend_fd].event, work->base, frontend_fd, EV_READ|EV_PERSIST, ssl_accept_from_frontend, (void*)work);
    event_add(&work->conn[frontend_fd].event, NULL);

    work->conn[frontend_fd].timer.handler = timer_node_free;
    work->conn[frontend_fd].timer.data = (void*)&work->conn[frontend_fd];               //本端节点
    timer_set_expire(&work->conn[frontend_fd].timer, get_local_time()+TIMEOUT);
    timer_insert(&work->timer, &work->conn[frontend_fd].timer);

    //前端HTTP数据
    work->conn[frontend_fd].http = (http_t*)malloc(sizeof(http_t));
    if(work->conn[frontend_fd].http == NULL)
        goto ErrP;
    memset(work->conn[frontend_fd].http, 0, sizeof(http_t));

    http_parser_settings_init(&work->conn[frontend_fd].http->settings);
    work->conn[frontend_fd].http->settings.on_message_begin = on_message_begin;
    work->conn[frontend_fd].http->settings.on_url = on_url;
    work->conn[frontend_fd].http->settings.on_status = on_status;
    work->conn[frontend_fd].http->settings.on_header_field = on_header_field;
    work->conn[frontend_fd].http->settings.on_header_value = on_header_value;
    work->conn[frontend_fd].http->settings.on_headers_complete = on_headers_complete;
    work->conn[frontend_fd].http->settings.on_body = on_body;
    work->conn[frontend_fd].http->settings.on_message_complete = on_message_complete;
    work->conn[frontend_fd].http->settings.on_chunk_header = on_chunk_header;
    work->conn[frontend_fd].http->settings.on_chunk_complete = on_chunk_complete;

    http_parser_init(&work->conn[frontend_fd].http->parser, HTTP_BOTH);
    work->conn[frontend_fd].http->parser.data = (void*)&work->conn[backend_fd];         //对端节点

    //后端数据
    work->conn[backend_fd].slot = slot;
    work->conn[backend_fd].fd = backend_fd;
    work->conn[backend_fd].ssl = NULL;
    work->conn[backend_fd].ip = strdup(conf->addr[slot].backend_ip);
    work->conn[backend_fd].port = conf->addr[slot].backend_port;
    work->conn[backend_fd].peer = &work->conn[frontend_fd];                             //对端节点

    event_assign(&work->conn[backend_fd].event, work->base, backend_fd, EV_READ|EV_PERSIST, tcp_recv_from_backend, (void*)work);
    event_add(&work->conn[backend_fd].event, NULL);

    work->conn[backend_fd].timer.handler = timer_node_free;
    work->conn[backend_fd].timer.data = (void*)&work->conn[backend_fd];                 //本端节点
    timer_set_expire(&work->conn[backend_fd].timer, get_local_time()+TIMEOUT+1);
    timer_insert(&work->timer, &work->conn[backend_fd].timer);

    //后端HTTP数据
    work->conn[backend_fd].http = (http_t*)malloc(sizeof(http_t));
    if(work->conn[backend_fd].http == NULL)
        goto ErrP;
    memset(work->conn[backend_fd].http, 0, sizeof(http_t));

    http_parser_settings_init(&work->conn[backend_fd].http->settings);
    work->conn[backend_fd].http->settings.on_message_begin = on_message_begin;
    work->conn[backend_fd].http->settings.on_url = on_url;
    work->conn[backend_fd].http->settings.on_status = on_status;
    work->conn[backend_fd].http->settings.on_header_field = on_header_field;
    work->conn[backend_fd].http->settings.on_header_value = on_header_value;
    work->conn[backend_fd].http->settings.on_headers_complete = on_headers_complete;
    work->conn[backend_fd].http->settings.on_body = on_body;
    work->conn[backend_fd].http->settings.on_message_complete = on_message_complete;
    work->conn[backend_fd].http->settings.on_chunk_header = on_chunk_header;
    work->conn[backend_fd].http->settings.on_chunk_complete = on_chunk_complete;

    http_parser_init(&work->conn[backend_fd].http->parser, HTTP_BOTH);
    work->conn[backend_fd].http->parser.data = (void*)&work->conn[frontend_fd];         //对端节点

    return;
ErrP:
    tcp_close(frontend_fd);
    tcp_close(backend_fd);
    if(ssl) SSL_free(ssl);
    if(work->conn[frontend_fd].ip)
    {
        free(work->conn[frontend_fd].ip);
        work->conn[frontend_fd].ip = NULL;
    }
    if(work->conn[backend_fd].ip)
    {
        free(work->conn[backend_fd].ip);
        work->conn[backend_fd].ip = NULL;
    }
    if(work->conn[frontend_fd].http)
    {
        free(work->conn[frontend_fd].http);
        work->conn[frontend_fd].http = NULL;
    }
    if(work->conn[backend_fd].http)
    {
        free(work->conn[backend_fd].http);
        work->conn[backend_fd].http = NULL;
    }
    return;
}

void ssl_accept_from_frontend(int fd, short events, void *data)
{
    int ret = 0;
    int slot = 0;
    config_t *conf = NULL;
    connection_t *peer = NULL;

    worker_t *work = (worker_t*)data;
    if(work == NULL)
        return;
    slot = work->conn[fd].slot;
    conf = &work->mast->conf;
    peer = work->conn[fd].peer;

    ret = ssl_accept(work->conn[fd].ssl);
    if(ret != 1)
    {
        log_err("%s ssl accept from frontend \"%s:%hu\" failed - %d: %s", conf->ctrl[slot].serverName, work->conn[fd].ip, work->conn[fd].port, errno, strerror(errno));
        goto ErrP;
    }
    log_debug("0, %s ssl accept from frontend \"%s:%hu\" succeed - %s", conf->ctrl[slot].serverName, work->conn[fd].ip, work->conn[fd].port, SSL_get_cipher(work->conn[fd].ssl));

    event_del(&work->conn[fd].event);
    event_assign(&work->conn[fd].event, work->base, fd, EV_READ|EV_PERSIST, ssl_read_from_frontend, (void*)work);
    event_add(&work->conn[fd].event, NULL);

    timer_remove(&work->timer, &work->conn[fd].timer);
    timer_set_expire(&work->conn[fd].timer, get_local_time()+TIMEOUT);
    timer_insert(&work->timer, &work->conn[fd].timer);

    return;
ErrP:
    event_conn_free(work, &work->conn[fd]);
    event_conn_free(work, peer);
    return;
}

void ssl_read_from_frontend(int fd, short events, void *data)
{
    int slot = 0;
    config_t *conf = NULL;
    connection_t *peer = NULL;

    int length = MAX_DATA_SIZE;
    unsigned char value[MAX_DATA_SIZE] = {0};

    worker_t *work = (worker_t*)data;
    if(work == NULL)
        return;
    slot = work->conn[fd].slot;
    conf = &work->mast->conf;
    peer = work->conn[fd].peer;

    length = ssl_read(work->conn[fd].ssl, (char*)value, length);
    if(length < 0)
    {
        log_err("%s ssl read data from frontend \"%s:%hu\" failed - %d: %s", conf->ctrl[slot].serverName, work->conn[fd].ip, work->conn[fd].port, errno, strerror(errno));
            goto ErrP;
    }
    else if(length == 0)
    {
        log_debug("%s ssl read RST from frontend \"%s:%hu\" succeed", conf->ctrl[slot].serverName, work->conn[fd].ip, work->conn[fd].port);
        goto ErrP;
    }
    log_debug("1, %s ssl read data from frontend \"%s:%hu\" succeed - %d: %s", conf->ctrl[slot].serverName, work->conn[fd].ip, work->conn[fd].port, length, value);

#ifdef _HTTP
    int ret = http_parser_execute(&work->conn[fd].http->parser, &work->conn[fd].http->settings, (char*)value, length);
    if(ret != length)
    {
        log_err("%s parse frontend \"%s:%hu\" HTTP failed - %s: %s", conf->ctrl[slot].serverName, work->conn[fd].ip, work->conn[fd].port, \
            http_errno_name(HTTP_PARSER_ERRNO(&work->conn[fd].http->parser)), http_errno_description(HTTP_PARSER_ERRNO(&work->conn[fd].http->parser)));
        goto ErrP;
    }
#else
    length = tcp_send(peer->fd, (char*)value, length);
    if(length < 0)
    {
        log_err("%s tcp send data to backend \"%s:%hu\" failed - %d: %s", conf->ctrl[slot].serverName, peer->ip, peer->port, errno, strerror(errno));
        goto ErrP;
    }
    log_debug("2, %s tcp send data to backend \"%s:%hu\" succeed - %d: %s", conf->ctrl[slot].serverName, peer->ip, peer->port, length, value);
#endif

    timer_remove(&work->timer, &work->conn[fd].timer);
    timer_set_expire(&work->conn[fd].timer, get_local_time()+TIMEOUT);
    timer_insert(&work->timer, &work->conn[fd].timer);

    return;
ErrP:
    event_conn_free(work, &work->conn[fd]);
    event_conn_free(work, peer);
    return;
}

void tcp_recv_from_backend(int fd, short events, void *data)
{
    int slot = 0;
    config_t *conf = NULL;
    connection_t *peer = NULL;

    int length = MAX_DATA_SIZE;
    unsigned char value[MAX_DATA_SIZE] = {0};

    worker_t *work = (worker_t*)data;
    if(work == NULL)
        return;
    slot = work->conn[fd].slot;
    conf = &work->mast->conf;
    peer = work->conn[fd].peer;

    length = tcp_recv(work->conn[fd].fd, (char*)value, length);
    if(length < 0)
    {
        log_err("%s tcp recv data from backend \"%s:%hu\" failed - %d: %s", conf->ctrl[slot].serverName, work->conn[fd].ip, work->conn[fd].port, errno, strerror(errno));
            goto ErrP;
    }
    else if(length == 0)
    {
        log_debug("%s tcp recv RST from backend \"%s:%hu\" succeed", conf->ctrl[slot].serverName, work->conn[fd].ip, work->conn[fd].port);
        goto ErrP;
    }
    log_debug("3, %s tcp recv data from backend \"%s:%hu\" succeed - %d: %s", conf->ctrl[slot].serverName, work->conn[fd].ip, work->conn[fd].port, length, value);

#ifdef _HTTP
    int ret = http_parser_execute(&work->conn[fd].http->parser, &work->conn[fd].http->settings, (char*)value, length);
    if(ret != length)
    {
        log_err("%s parse backend \"%s:%hu\" HTTP failed - %s: %s", conf->ctrl[slot].serverName, work->conn[fd].ip, work->conn[fd].port, \
            http_errno_name(HTTP_PARSER_ERRNO(&work->conn[fd].http->parser)), http_errno_description(HTTP_PARSER_ERRNO(&work->conn[fd].http->parser)));
        goto ErrP;
    }
#else
    length = ssl_write(peer->ssl, (char*)value, length);
    if(length <= 0)
    {
        log_err("%s ssl write data to frontend \"%s:%hu\" failed - %d: %s", conf->ctrl[slot].serverName, peer->ip, peer->port, errno, strerror(errno));
        goto ErrP;
    }
    log_debug("4, %s ssl write data to frontend \"%s:%hu\" succeed - %d: %s", conf->ctrl[slot].serverName, peer->ip, peer->port, length, value);
#endif

    timer_remove(&work->timer, &work->conn[fd].timer);
    timer_set_expire(&work->conn[fd].timer, get_local_time()+TIMEOUT);
    timer_insert(&work->timer, &work->conn[fd].timer);

    return;
ErrP:
    event_conn_free(work, &work->conn[fd]);
    event_conn_free(work, peer);
    return;
}

void event_conn_free(worker_t *work, connection_t *conn)
{
    if(work == NULL || conn == NULL)
        return;

    conn->slot = -1;
    if(conn->ssl)
    {
        list_del_init(&conn->list);
        SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }
    if(conn->fd > 0)
    {
        log_debug("fd \"%d\" was closed", conn->fd);
        timer_remove(&work->timer, &conn->timer);
        event_del(&conn->event);
        tcp_close(conn->fd);
        conn->fd = -1;
    }
    if(conn->ip)
    {
        free(conn->ip);
        conn->ip = NULL;
    }
    conn->port = 0;
    if(conn->http)
    {
        free(conn->http);
        conn->http = NULL;
    }
    conn->peer = NULL;
}
