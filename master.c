#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "log.h"
#include "utils.h"
#include "signals.h"
#include "options.h"
#include "fd_utils.h"
#include "tcp_utils.h"
#include "setproctitle.h"
#include "process.h"
#include "worker.h"
#include "master.h"

#define MAX_BACKLOG_NUM 256

int socket_init(char *ip, unsigned short port)
{
    int rv = 0;
    int fd = 0;

    if(ip == NULL || port < 0)
    {
        log_err("socket ip or port was NULL - %s:%hu", ip, port);
        return -1;
    }

    fd = tcp_socket();
    if(fd < 0)
    {
        log_err("tcp_socket failed - %d: %s", errno, strerror(errno));
        return -1;
    }

    rv = tcp_bind(fd, ip, port);
    if(rv < 0)
    {
        log_err("tcp_bind to \"%s:%hu\" failed - %d: %s", ip, port, errno, strerror(errno));
        goto ErrP;
    }

    rv = tcp_listen(fd, MAX_BACKLOG_NUM);
    if(rv < 0)
    {
        log_err("tcp_listen failed - %d: %s", errno, strerror(errno));
        goto ErrP;
    }

    return fd;
ErrP:
    socket_exit(fd);
    return -1;
}

void socket_exit(int fd)
{
    tcp_close(fd);
}

int service_master_process(void *data)
{
    int ret = 0;
    int i = 0;
    char *env = NULL;
    struct event stop;
    master_t *mast = NULL;
    proxy_t *proxy = NULL;

#ifndef __DEBUG__
    ret = set_conn_limit(MAX_CONN_NUM);
    if(ret < 0)
    {
        log_err("setrlimit RLIMIT_NOFILE failed - %d: %s", errno, strerror(errno));
        return EXIT_FAILURE;
    }
#endif

    mast = (master_t*)malloc(sizeof(master_t));
    if(mast == NULL)
    {
        log_err("malloc memory failed - %d: %s", errno, strerror(errno));
        return EXIT_FAILURE;
    }
    memset(mast, 0, sizeof(master_t));

    proxy = &mast->proxy;
    ret = cfg_init(proxy, config);
    if(ret < 0)
    {
        log_err("config \"%s\" was invalid - %d: %s", config, errno, strerror(errno));
        goto ErrP;
    }
    log_set_level(log_get_level(proxy->global.level));

    mast->workNumber = proxy->global.number*get_proc_num();
    mast->workArray = (worker_t*)malloc(mast->workNumber*sizeof(worker_t));
    if(mast->workArray == NULL)
    {
        log_err("malloc memory failed - %d: %s", errno, strerror(errno));
        goto ErrP;
    }
    memset(mast->workArray, 0, mast->workNumber*sizeof(worker_t));

    for(i = 0; i < proxy->serverNumber; i++)
    {
        if(proxy->serverArray[i].isEnable)
        {
            mast->fd[i] = socket_init(proxy->serverArray[i].serverIP, proxy->serverArray[i].serverPort);
            if(mast->fd[i] < 0)
            {
                log_err("socket init \"%s\" failed - \"%s:%hu\"", proxy->serverArray[i].serverName, proxy->serverArray[i].serverIP, proxy->serverArray[i].serverPort);
                goto ErrP;
            }
            log_info("\"%s\" - \"%s:%hu\"", proxy->serverArray[i].serverName, proxy->serverArray[i].serverIP, proxy->serverArray[i].serverPort);
        }
    }

    for(i = 0; i < mast->workNumber; i++)
    {
        mast->workArray[i].slot = i;
        mast->workArray[i].mast = mast;
        ret = fd_pair(mast->workArray[i].sockfd);
        if(ret < 0)
        {
            log_err("socketpair failed - %d: %s", errno, strerror(errno));
            goto ErrP;
        }
        mast->workArray[i].pid = service_proc_fork(service_worker_process, (void*)&mast->workArray[i]);
        if(mast->workArray[i].pid < 0)
        {
            log_err("service fork process failed - %d: %s", errno, strerror(errno));
            goto ErrP;
        }
        log_info("service fork process succeed - \"%d\"", mast->workArray[i].pid);
        fd_close(mast->workArray[i].sockfd[1]);
    }

    mast->base = event_base_new();
    if(mast->base == NULL)
    {
        log_err("event_base_new failed - %d: %s", errno, strerror(errno));
        goto ErrP;
    }
    env = os_setproctitle(os_argc, os_argv, "proxy: master process");

    evsignal_assign(&stop, mast->base, SIGINT, on_stop, (void*)mast->base);
    evsignal_add(&stop, NULL);

    signals_register();
    event_base_dispatch(mast->base);

    evsignal_del(&stop);
    if(mast)
    {
        if(mast->workArray)
        {
            for(i = 0; i < mast->workNumber; i++) fd_close(mast->workArray[i].sockfd[0]);
            if(mast->workArray) free(mast->workArray);
        }
        if(proxy)
        {
            for(i = 0; i < proxy->serverNumber; i++) socket_exit(mast->fd[i]);
            cfg_exit(proxy);
        }
        if(mast->base) event_base_free(mast->base);
        free(mast);
    }
    if(env) free(env);
    return EXIT_SUCCESS;
ErrP:
    if(mast)
    {
        if(mast->workArray)
        {
            for(i = 0; i < mast->workNumber; i++) fd_close(mast->workArray[i].sockfd[0]);
            if(mast->workArray) free(mast->workArray);
        }
        if(proxy)
        {
            for(i = 0; i < proxy->serverNumber; i++) socket_exit(mast->fd[i]);
            cfg_exit(proxy);
        }
        if(mast->base) event_base_free(mast->base);
        free(mast);
    }
    if(env) free(env);
    return EXIT_FAILURE;
}
