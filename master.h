#ifndef __MASTER_H__
#define __MASTER_H__

#include "ini_handler.h"

typedef struct master_s
{
    int fd[MAX_COUNT_NUM];
    config_t conf;
}master_t;

int socket_init(char *ip, unsigned short port);

void socket_exit(int fd);

int service_master_process(void *data);

#endif
