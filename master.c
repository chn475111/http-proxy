#include <errno.h>
#include <string.h>
#include <unistd.h>
#include "log.h"
#include "utils.h"
#include "tcp_utils.h"
#include "ini.h"
#include "ini_handler.h"
#include "proc.h"
#include "worker.h"
#include "master.h"

int socket_init(char *ip, unsigned short port)
{
    int rv = 0;
    int fd = 0;

    if(ip == NULL || port <= 0)
        return -1;

    fd = tcp_socket();
    if(fd == -1)
    {
        log_err("socket fd failed - %d: %s", errno, strerror(errno));
        return -1;
    }

    rv = tcp_bind(fd, ip, port);
    if(rv == -1)
    {
        log_err("bind fd failed - %d: %s", errno, strerror(errno));
        goto ErrP;
    }

    rv = tcp_listen(fd, 128);
    if(rv == -1)
    {
        log_err("listen fd failed - %d: %s", errno, strerror(errno));
        goto ErrP;
    }

    return fd;
ErrP:
    socket_exit(fd);
    return -1;
}

void socket_exit(int fd)
{
    if(fd > 0) close(fd);
}

int service_master_process(void *data)
{
    int ret = 0;
    int loop = 0;
    master_t *mast = NULL;
    const char *filename = data;
    int nproc = get_proc_num();

#if 1
    ret = set_conn_limit(MAX_CONN_NUM);
    if(ret == -1)
    {
        log_err("setrlimit RLIMIT_NOFILE failed - %d: %s", errno, strerror(errno));
        return EXIT_FAILURE;
    }
#endif

    mast = (master_t*)malloc(sizeof(master_t));
    if(mast == NULL)
    {
        log_err("malloc memory from OS failed - %d: %s", errno, strerror(errno));
        return EXIT_FAILURE;
    }
    memset(mast, 0, sizeof(master_t));

    ret = ini_parse(filename, config_handler, (void*)&mast->conf);
    if(ret < 0 || mast->conf.count < 1 || mast->conf.count > MAX_COUNT_NUM)
    {
        log_err("parse \"%s\" failed - %d: %s", filename, errno, strerror(errno));
        goto ErrP;
    }
    log_set_level(log_get_level(mast->conf.level));

    for(loop = 0; loop < mast->conf.count; loop ++)
    {
        if(mast->conf.ctrl[loop].isEnable)
        {
            mast->fd[loop] = socket_init(mast->conf.addr[loop].server_ip, mast->conf.addr[loop].server_port);
            if(mast->fd[loop] == -1)
            {
                log_err("socket init server%d failed - %s:%hu", loop, mast->conf.addr[loop].server_ip, mast->conf.addr[loop].server_port);
                goto ErrP;
            }
            log_info("server%d - %s:%hu", loop, mast->conf.addr[loop].server_ip, mast->conf.addr[loop].server_port);
        }
    }

    for(loop = 0; loop < nproc; loop ++)
    {
        ret = service_fork_proc(service_worker_process, (void*)mast);
        if(ret <= 0)
        {
            log_err("service fork proc failed - %d: %s", errno, strerror(errno));
            goto ErrP;
        }
        log_info("service fork proc succeed - %d", ret);
    }

    if(mast)
    {
        config_free((void*)&mast->conf);
        for(loop = 0; loop < mast->conf.count; loop ++) socket_exit(mast->fd[loop]);
        free(mast);
    }
    return EXIT_SUCCESS;
ErrP:
    if(mast)
    {
        config_free((void*)&mast->conf);
        for(loop = 0; loop < mast->conf.count; loop ++) socket_exit(mast->fd[loop]);
        free(mast);
    }
    return EXIT_FAILURE;
}
