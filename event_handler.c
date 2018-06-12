#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "log.h"
#include "fd_utils.h"
#include "tcp_utils.h"
#include "worker.h"
#include "master.h"
#include "event_handler.h"

static int error_code = SSL_ERROR_NONE;
static const char *error_string[] = {
    [SSL_ERROR_NONE]                = "SSL_ERROR_NONE",
    [SSL_ERROR_SSL]                 = "SSL_ERROR_SSL",
    [SSL_ERROR_WANT_READ]           = "SSL_ERROR_WANT_READ",
    [SSL_ERROR_WANT_WRITE]          = "SSL_ERROR_WANT_WRITE",
    [SSL_ERROR_WANT_X509_LOOKUP]    = "SSL_ERROR_WANT_X509_LOOKUP",
    [SSL_ERROR_SYSCALL]             = "SSL_ERROR_SYSCALL",
    [SSL_ERROR_ZERO_RETURN]         = "SSL_ERROR_ZERO_RETURN",
    [SSL_ERROR_WANT_CONNECT]        = "SSL_ERROR_WANT_CONNECT",
    [SSL_ERROR_WANT_ACCEPT]         = "SSL_ERROR_WANT_ACCEPT"
};

void tcp_accept_from_frontend(int fd, short events, void *data)
{
    int frontend_fd = 0;
    char frontend_ip[MAX_IP_SIZE] = {0};
    unsigned short frontend_port = 0;

    if(data == NULL)
    {
        log_crit("tcp internal error - %p", data);
        return;
    }

    worker_t *work = (worker_t*)data;
    proxy_t *proxy = &work->mast->proxy;

    int slot = work->conn[fd].slot;
    char *serverName = proxy->serverArray[slot].serverName;

    struct timeval tv = 
    {
        .tv_sec = proxy->global.timeout,
        .tv_usec = 0
    };

    frontend_fd = tcp_accept(fd, frontend_ip, MAX_IP_SIZE, &frontend_port);
    if(frontend_fd < 0)
    {
        if(errno != EAGAIN) log_err("0, \"%s\" tcp accept from frontend failed - %d: %s", serverName, errno, strerror(errno));
        return;
    }
    log_debug("0, \"%s\" tcp accept from frontend \"%s:%hu\" succeed", serverName, frontend_ip, frontend_port);

    SSL *ssl = SSL_new(work->ctx[slot]);
    SSL_set_fd(ssl, frontend_fd);

    //前端节点
    work->conn[frontend_fd].slot = slot;
    work->conn[frontend_fd].fd = frontend_fd;
    work->conn[frontend_fd].ssl = ssl;
    strncpy(work->conn[frontend_fd].ip, frontend_ip, MAX_IP_SIZE);
    work->conn[frontend_fd].port = frontend_port;
    work->conn[frontend_fd].http = http_new(&work->conn[frontend_fd]);
    work->conn[frontend_fd].membuf = membuf_new(MAX_DATA_SIZE);

    event_assign(&work->conn[frontend_fd].event, work->base, frontend_fd, EV_TIMEOUT|EV_READ, ssl_accept_from_frontend, (void*)work);
    event_add(&work->conn[frontend_fd].event, &tv);
    return;
}

void ssl_accept_from_frontend(int fd, short events, void *data)
{
    int ret = 0;
    int backend_fd = 0;

    if(data == NULL)
    {
        log_crit("tcp internal error - %p", data);
        return;
    }

    worker_t *work = (worker_t*)data;
    proxy_t *proxy = &work->mast->proxy;

    int slot = work->conn[fd].slot;
    char *serverName = proxy->serverArray[slot].serverName;
    backend_t *backend = proxy->serverArray[slot].backend;

    if(events & EV_TIMEOUT)
    {
        log_warning("fd \"%d\" was timeout - \"%s:%hu\"", fd, work->conn[fd].ip, work->conn[fd].port);
        goto ErrP;
    }

    struct timeval tv = 
    {
        .tv_sec = proxy->global.timeout,
        .tv_usec = 0
    };

    SSL *ssl = work->conn[fd].ssl;
    if(!SSL_is_init_finished(ssl))
    {
        ret = SSL_accept(ssl);
        if(ret <= 0)
        {
            error_code = SSL_get_error(ssl, ret);
            switch(error_code)
            {
                case SSL_ERROR_WANT_READ:
                    log_debug("1, \"%s\" ssl accept from frontend \"%s:%hu\" failed - %s", serverName, work->conn[fd].ip, work->conn[fd].port, error_string[error_code]);
                    event_assign(&work->conn[fd].event, work->base, fd, EV_TIMEOUT|EV_READ, ssl_accept_from_frontend, (void*)work);
                    event_add(&work->conn[fd].event, &tv);
                    return;
                case SSL_ERROR_WANT_WRITE:
                    log_warning("1, \"%s\" ssl accept from frontend \"%s:%hu\" failed - %s", serverName, work->conn[fd].ip, work->conn[fd].port, error_string[error_code]);
                    event_assign(&work->conn[fd].event, work->base, fd, EV_TIMEOUT|EV_WRITE, ssl_accept_from_frontend, (void*)work);
                    event_add(&work->conn[fd].event, &tv);
                    return;
                case SSL_ERROR_ZERO_RETURN:
                    log_warning("1, \"%s\" ssl accept \"RST\" from frontend \"%s:%hu\" succeed - %s", serverName, work->conn[fd].ip, work->conn[fd].port, error_string[error_code]);
                    goto ErrP;
                case SSL_ERROR_SYSCALL:
                    log_err("1, \"%s\" ssl accept from frontend \"%s:%hu\" failed - %s %d: %s", serverName, work->conn[fd].ip, work->conn[fd].port, error_string[error_code], errno, strerror(errno));
                    goto ErrP;
                case SSL_ERROR_SSL:
                    log_err("1, \"%s\" ssl accept from frontend \"%s:%hu\" failed - %s", serverName, work->conn[fd].ip, work->conn[fd].port, error_string[error_code]);
                    goto ErrP;
                default:
                    log_err("1, \"%s\" ssl accept from frontend \"%s:%hu\" failed - %s", serverName, work->conn[fd].ip, work->conn[fd].port, error_string[error_code]);
                    goto ErrP;
            }
        }
    }
    log_debug("1, \"%s\" ssl accept from frontend \"%s:%hu\" succeed - %s", serverName, work->conn[fd].ip, work->conn[fd].port, SSL_get_cipher(ssl));

    backend_fd = tcp_socket();
    if(backend_fd < 0)
    {
        log_err("\"%s\" tcp socket failed - %d: %s", serverName, errno, strerror(errno));
        goto ErrP;
    }

    ret = tcp_connect(backend_fd, backend->backendIP, backend->backendPort);
    if(ret < 0)
    {
        if(errno == EINPROGRESS)
        {
            log_debug("2, \"%s\" tcp connect to backend \"%s:%hu\" failed - %d: %s", serverName, backend->backendIP, backend->backendPort, errno, strerror(errno));
            goto EndP;
        }
        log_err("2, \"%s\" tcp connect to backend \"%s:%hu\" failed - %d: %s", serverName, backend->backendIP, backend->backendPort, errno, strerror(errno));
        goto ErrP;
    }
    log_debug("2, \"%s\" tcp connect to backend \"%s:%hu\" succeed", serverName, backend->backendIP, backend->backendPort);

    //前端节点
    work->conn[fd].peer = &work->conn[backend_fd];                  //对端节点

    event_assign(&work->conn[fd].event, work->base, fd, EV_TIMEOUT|EV_READ, ssl_read_from_frontend, (void*)work);
    event_add(&work->conn[fd].event, &tv);

    //后端节点
    work->conn[backend_fd].slot = slot;
    work->conn[backend_fd].fd = backend_fd;
    strncpy(work->conn[backend_fd].ip, backend->backendIP, MAX_IP_SIZE);
    work->conn[backend_fd].port = backend->backendPort;
    work->conn[backend_fd].http = http_new(&work->conn[backend_fd]);
    work->conn[backend_fd].membuf = membuf_new(MAX_DATA_SIZE);
    work->conn[backend_fd].peer = &work->conn[fd];                  //对端节点

    event_assign(&work->conn[backend_fd].event, work->base, backend_fd, EV_TIMEOUT|EV_READ, tcp_recv_from_backend, (void*)work);
    event_add(&work->conn[backend_fd].event, &tv);
    return;
EndP:
    //前端节点
    work->conn[fd].peer = &work->conn[backend_fd];                  //对端节点

    //后端节点
    work->conn[backend_fd].slot = slot;
    work->conn[backend_fd].fd = backend_fd;
    strncpy(work->conn[backend_fd].ip, backend->backendIP, MAX_IP_SIZE);
    work->conn[backend_fd].port = backend->backendPort;
    work->conn[backend_fd].http = http_new(&work->conn[backend_fd]);
    work->conn[backend_fd].membuf = membuf_new(MAX_DATA_SIZE);
    work->conn[backend_fd].peer = &work->conn[fd];                 //对端节点

    event_assign(&work->conn[backend_fd].event, work->base, backend_fd, EV_TIMEOUT|EV_WRITE, tcp_connect_to_backend, (void*)work);
    event_add(&work->conn[backend_fd].event, &tv);
    return;
ErrP:
    ERR_print_errors_fp(stderr);
    tcp_conn_free(&work->conn[fd]);
    tcp_close(backend_fd);
    return;
}

void tcp_connect_to_backend(int fd, short events, void *data)
{
    int ret = 0;
    int optval = 0;
    socklen_t optlen = sizeof(int);

    if(data == NULL)
    {
        log_crit("tcp internal error - %p", data);
        return;
    }

    worker_t *work = (worker_t*)data;
    proxy_t *proxy = &work->mast->proxy;
    connection_t *peer = work->conn[fd].peer;

    int slot = work->conn[fd].slot;
    char *serverName = proxy->serverArray[slot].serverName;

    struct timeval tv = 
    {
        .tv_sec = proxy->global.timeout,
        .tv_usec = 0
    };

    if(events & EV_TIMEOUT)
    {
        log_warning("fd \"%d\" was timeout - \"%s:%hu\"", fd, work->conn[fd].ip, work->conn[fd].port);
        goto ErrP;
    }

    ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, (char*)&optval, &optlen);
    if(ret != 0 || optval != 0)
    {
        log_err("2, \"%s\" tcp connect to backend \"%s:%hu\" failed - %d: %s", serverName, work->conn[fd].ip, work->conn[fd].port, errno, strerror(errno));
        goto ErrP;
    }
    log_debug("2, \"%s\" tcp connect to backend \"%s:%hu\" succeed", serverName, work->conn[fd].ip, work->conn[fd].port);

    event_assign(&peer->event, work->base, peer->fd, EV_TIMEOUT|EV_READ, ssl_read_from_frontend, (void*)work);
    event_add(&peer->event, &tv);

    event_assign(&work->conn[fd].event, work->base, fd, EV_TIMEOUT|EV_READ, tcp_recv_from_backend, (void*)work);
    event_add(&work->conn[fd].event, &tv);
    return;
ErrP:
    tcp_conn_free(&work->conn[fd]);
    tcp_conn_free(peer);
    return;
}

void ssl_read_from_frontend(int fd, short events, void *data)
{
    if(data == NULL)
    {
        log_crit("tcp internal error - %p", data);
        return;
    }

    worker_t *work = (worker_t*)data;
    proxy_t *proxy = &work->mast->proxy;
    connection_t *peer = work->conn[fd].peer;
    membuf_t *membuf = work->conn[fd].membuf;

    int slot = work->conn[fd].slot;
    char *proxyType = proxy->serverArray[slot].proxyType;
    char *serverName = proxy->serverArray[slot].serverName;

    struct timeval tv = 
    {
        .tv_sec = proxy->global.timeout,
        .tv_usec = 0
    };

    if(events & EV_TIMEOUT)
    {
        log_warning("fd \"%d\" was timeout - \"%s:%hu\"", fd, work->conn[fd].ip, work->conn[fd].port);
        goto ErrP;
    }

do{
    membuf->mlen = 0;
    membuf->mpos = membuf->buffer;
    membuf->mlen = SSL_read(work->conn[fd].ssl, membuf->buffer, membuf->length);
    if(membuf->mlen <= 0)
    {
        error_code = SSL_get_error(work->conn[fd].ssl, membuf->mlen);
        if(error_code == SSL_ERROR_ZERO_RETURN)
        {
            log_debug("3, \"%s\" ssl read \"RST\" from frontend \"%s:%hu\" succeed - %s", serverName, work->conn[fd].ip, work->conn[fd].port, error_string[error_code]);
            goto ErrP;
        }
        log_err("3, \"%s\" ssl read data from frontend \"%s:%hu\" failed - %s", serverName, work->conn[fd].ip, work->conn[fd].port, error_string[error_code]);
        goto ErrP;
    }
    log_debug("3, \"%s\" ssl read data from frontend \"%s:%hu\" succeed - %d: %s", serverName, work->conn[fd].ip, work->conn[fd].port, membuf->mlen, membuf->mpos);

    if(strcasecmp(proxyType, "http") == 0)
    {
        int ret = http_exec(work->conn[fd].http, (const char*)membuf->mpos, membuf->mlen);
        if(ret < 0)
        {
            log_err("\"%s\" http parser failed - \"%s:%hu\"", serverName, work->conn[fd].ip, work->conn[fd].port);
            goto ErrP;
        }
    }

    membuf->mlen = tcp_send(peer->fd, membuf->mpos, membuf->mlen);
    if(membuf->mlen < 0)
    {
        if(errno == EAGAIN)
        {
            log_warning("4, \"%s\" tcp send data to backend \"%s:%hu\" failed - %d: %s", serverName, peer->ip, peer->port, errno, strerror(errno));
            goto EndP;
        }
        log_err("4, \"%s\" tcp send data to backend \"%s:%hu\" failed - %d: %s", serverName, peer->ip, peer->port, errno, strerror(errno));
        goto ErrP;
    }
    log_debug("4, \"%s\" tcp send data to backend \"%s:%hu\" succeed - %d: %s", serverName, peer->ip, peer->port, membuf->mlen, membuf->mpos);
}while(SSL_pending(work->conn[fd].ssl) > 0);

    event_assign(&work->conn[fd].event, work->base, fd, EV_TIMEOUT|EV_READ, ssl_read_from_frontend, (void*)work);
    event_add(&work->conn[fd].event, &tv);
    return;
EndP:
    if(event_initialized(&peer->event)) event_del(&peer->event);
    event_assign(&peer->event, work->base, peer->fd, EV_TIMEOUT|EV_WRITE, tcp_send_to_backend, (void*)work);
    event_add(&peer->event, &tv);
    return;
ErrP:
    ERR_print_errors_fp(stderr);
    tcp_conn_free(&work->conn[fd]);
    tcp_conn_free(peer);
    return;
}

void tcp_send_to_backend(int fd, short events, void *data)
{
    if(data == NULL)
    {
        log_crit("tcp internal error - %p", data);
        return;
    }

    worker_t *work = (worker_t*)data;
    proxy_t *proxy = &work->mast->proxy;
    connection_t *peer = work->conn[fd].peer;
    membuf_t *membuf = peer->membuf;

    int slot = work->conn[fd].slot;
    char *proxyType = proxy->serverArray[slot].proxyType;
    char *serverName = proxy->serverArray[slot].serverName;

    struct timeval tv = 
    {
        .tv_sec = proxy->global.timeout,
        .tv_usec = 0
    };

    if(events & EV_TIMEOUT)
    {
        log_warning("fd \"%d\" was timeout - \"%s:%hu\"", fd, work->conn[fd].ip, work->conn[fd].port);
        goto ErrP;
    }

    membuf->mlen = tcp_send(fd, membuf->mpos, membuf->mlen);
    if(membuf->mlen < 0)
    {
        log_err("4, \"%s\" tcp send data to backend \"%s:%hu\" failed - %d: %s", serverName, work->conn[fd].ip, work->conn[fd].port, errno, strerror(errno));
        goto ErrP;
    }
    log_debug("4, \"%s\" tcp send data to backend \"%s:%hu\" succeed - %d: %s", serverName, work->conn[fd].ip, work->conn[fd].port, membuf->mlen, membuf->mpos);

while(SSL_pending(peer->ssl) > 0)
{
    membuf->mlen = 0;
    membuf->mpos = membuf->buffer;
    membuf->mlen = SSL_read(peer->ssl, membuf->buffer, membuf->length);
    if(membuf->mlen <= 0)
    {
        error_code = SSL_get_error(peer->ssl, membuf->mlen);
        log_err("3, \"%s\" ssl read data from frontend \"%s:%hu\" failed - %s", serverName, peer->ip, peer->port, error_string[error_code]);
        goto ErrP;
    }
    log_debug("3, \"%s\" ssl read data from frontend \"%s:%hu\" succeed - %d: %s", serverName, peer->ip, peer->port, membuf->mlen, membuf->mpos);

    if(strcasecmp(proxyType, "http") == 0)
    {
        int ret = http_exec(peer->http, (const char*)membuf->mpos, membuf->mlen);
        if(ret < 0)
        {
            log_err("\"%s\" http parser failed - \"%s:%hu\"", serverName, peer->ip, peer->port);
            goto ErrP;
        }
    }

    membuf->mlen = tcp_send(work->conn[fd].fd, membuf->mpos, membuf->mlen);
    if(membuf->mlen < 0)
    {
        log_err("4, \"%s\" tcp send data to backend \"%s:%hu\" failed - %d: %s", serverName, work->conn[fd].ip, work->conn[fd].port, errno, strerror(errno));
        goto ErrP;
    }
    log_debug("4, \"%s\" tcp send data to backend \"%s:%hu\" succeed - %d: %s", serverName, work->conn[fd].ip, work->conn[fd].port, membuf->mlen, membuf->mpos);
}

    event_assign(&peer->event, work->base, peer->fd, EV_TIMEOUT|EV_READ, ssl_read_from_frontend, (void*)work);
    event_add(&peer->event, &tv);

    event_assign(&work->conn[fd].event, work->base, fd, EV_TIMEOUT|EV_READ, tcp_recv_from_backend, (void*)work);
    event_add(&work->conn[fd].event, &tv);
    return;
ErrP:
    ERR_print_errors_fp(stderr);
    tcp_conn_free(&work->conn[fd]);
    tcp_conn_free(peer);
    return;
}

void tcp_recv_from_backend(int fd, short events, void *data)
{
    if(data == NULL)
    {
        log_crit("tcp internal error - %p", data);
        return;
    }

    worker_t *work = (worker_t*)data;
    proxy_t *proxy = &work->mast->proxy;
    connection_t *peer = work->conn[fd].peer;
    membuf_t *membuf = work->conn[fd].membuf;

    int slot = work->conn[fd].slot;
    char *proxyType = proxy->serverArray[slot].proxyType;
    char *serverName = proxy->serverArray[slot].serverName;

    struct timeval tv = 
    {
        .tv_sec = proxy->global.timeout,
        .tv_usec = 0
    };

    if(events & EV_TIMEOUT)
    {
        log_warning("fd \"%d\" was timeout - \"%s:%hu\"", fd, work->conn[fd].ip, work->conn[fd].port);
        goto ErrP;
    }

    membuf->mlen = 0;
    membuf->mpos = membuf->buffer;
    membuf->mlen = tcp_recv(fd, membuf->buffer, membuf->length);
    if(membuf->mlen < 0)
    {
        if(errno != ECONNRESET) log_err("5, \"%s\" tcp recv data from backend \"%s:%hu\" failed - %d: %s", serverName, work->conn[fd].ip, work->conn[fd].port, errno, strerror(errno));
        goto ErrP;
    }
    else if(membuf->mlen == 0)
    {
        log_debug("5, \"%s\" tcp recv \"RST\" from backend \"%s:%hu\" succeed", serverName, work->conn[fd].ip, work->conn[fd].port);
        goto ErrP;
    }
    log_debug("5, \"%s\" tcp recv data from backend \"%s:%hu\" succeed - %d: %s", serverName, work->conn[fd].ip, work->conn[fd].port, membuf->mlen, membuf->mpos);

    if(strcasecmp(proxyType, "http") == 0)
    {
        int ret = http_exec(work->conn[fd].http, (const char*)membuf->mpos, membuf->mlen);
        if(ret < 0)
        {
            log_err("\"%s\" http parser failed - \"%s:%hu\"", serverName, work->conn[fd].ip, work->conn[fd].port);
            goto ErrP;
        }
    }

    membuf->mlen = SSL_write(peer->ssl, membuf->mpos, membuf->mlen);
    if(membuf->mlen <= 0)
    {
        error_code = SSL_get_error(peer->ssl, membuf->mlen);
        if(error_code == SSL_ERROR_WANT_WRITE)
        {
            log_warning("6, \"%s\" ssl write data to frontend \"%s:%hu\" failed - %s", serverName, peer->ip, peer->port, error_string[error_code]);
            goto EndP;
        }
        log_err("6, \"%s\" ssl write data to frontend \"%s:%hu\" failed - %s", serverName, peer->ip, peer->port, error_string[error_code]);
        goto ErrP;
    }
    log_debug("6, \"%s\" ssl write data to frontend \"%s:%hu\" succeed - %d: %s", serverName, peer->ip, peer->port, membuf->mlen, membuf->mpos);

    event_assign(&work->conn[fd].event, work->base, fd, EV_TIMEOUT|EV_READ, tcp_recv_from_backend, (void*)work);
    event_add(&work->conn[fd].event, &tv);
    return;
EndP:
    if(event_initialized(&peer->event)) event_del(&peer->event);
    event_assign(&peer->event, work->base, peer->fd, EV_TIMEOUT|EV_WRITE, ssl_write_to_frontend, (void*)work);
    event_add(&peer->event, &tv);
    return;
ErrP:
    ERR_print_errors_fp(stderr);
    tcp_conn_free(&work->conn[fd]);
    tcp_conn_free(peer);
    return;
}

void ssl_write_to_frontend(int fd, short events, void *data)
{
    if(data == NULL)
    {
        log_crit("tcp internal error - %p", data);
        return;
    }

    worker_t *work = (worker_t*)data;
    proxy_t *proxy = &work->mast->proxy;
    connection_t *peer = work->conn[fd].peer;
    membuf_t *membuf = peer->membuf;

    int slot = work->conn[fd].slot;
    char *serverName = proxy->serverArray[slot].serverName;

    struct timeval tv = 
    {
        .tv_sec = proxy->global.timeout,
        .tv_usec = 0
    };

    if(events & EV_TIMEOUT)
    {
        log_warning("fd \"%d\" was timeout - \"%s:%hu\"", fd, work->conn[fd].ip, work->conn[fd].port);
        goto ErrP;
    }

    membuf->mlen = SSL_write(work->conn[fd].ssl, membuf->mpos, membuf->mlen);
    if(membuf->mlen <= 0)
    {
        error_code = SSL_get_error(work->conn[fd].ssl, membuf->mlen);
        log_err("6, \"%s\" ssl write data to frontend \"%s:%hu\" failed - %s", serverName, work->conn[fd].ip, work->conn[fd].port, error_string[error_code]);
        goto ErrP;
    }
    log_debug("6, \"%s\" ssl write data to frontend \"%s:%hu\" succeed - %d: %s", serverName, work->conn[fd].ip, work->conn[fd].port, membuf->mlen, membuf->mpos);

    event_assign(&peer->event, work->base, peer->fd, EV_TIMEOUT|EV_READ, tcp_recv_from_backend, (void*)work);
    event_add(&peer->event, &tv);

    event_assign(&work->conn[fd].event, work->base, fd, EV_TIMEOUT|EV_READ, ssl_read_from_frontend, (void*)work);
    event_add(&work->conn[fd].event, &tv);
    return;
ErrP:
    ERR_print_errors_fp(stderr);
    tcp_conn_free(&work->conn[fd]);
    tcp_conn_free(peer);
    return;
}

void tcp_conn_free(connection_t *conn)
{
    if(conn == NULL || conn->fd <= 0)
        return;

    log_debug("fd \"%d\" was closed - \"%s:%hu\"", conn->fd, conn->ip, conn->port);

    conn->slot = -1;
    if(conn->ssl)
    {
        SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }
    tcp_close(conn->fd);
    conn->fd = -1;
    if(event_initialized(&conn->event)) event_del(&conn->event);

    conn->ip[0] = 0;
    conn->port = 0;
    if(conn->http)
    {
        http_delete(conn->http);
        conn->http = NULL;
    }
    if(conn->membuf)
    {
        membuf_delete(conn->membuf);
        conn->membuf = NULL;
    }
    conn->peer = NULL;
}
