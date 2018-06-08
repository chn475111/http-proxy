#ifndef __MASTER_H__
#define __MASTER_H__

#include "cfg_handler.h"

typedef struct master_s
{
    proxy_t proxy;                          //CFG配置
    int fd[MAX_SERVER_NUM];                 //FD句柄数组
    int workNumber;                         //工作进程个数
    struct worker_s *workArray;             //工作进程数组
    struct event_base *base;                //Base事件句柄
}master_t;

int socket_init(char *ip, unsigned short port);

void socket_exit(int fd);

int service_master_process(void *data);

#endif
