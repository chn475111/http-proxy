#ifndef __WORKER_H__
#define __WORKER_H__

#include "connection.h"
#include "cfg_handler.h"

typedef struct worker_s
{
    int slot;                               //工作进程索引
    pid_t pid;                              //工作进程PID
    int sockfd[2];                          //父进程: sockfd[0]; 子进程: sockfd[1]
    SSL_CTX *ctx[MAX_SERVER_NUM];           //CTX句柄数组
    connection_t conn[MAX_CONN_NUM];        //Connection连接数组
    connection_t *hhash;                    //Connection哈希句柄
    struct list_head hlist;                 //Connection链表头节点
    struct event timer;                     //Timer计时器事件
    struct event_base *base;                //Base事件句柄
    struct master_s *mast;                  //Master句柄
}worker_t;

void on_stop(int fd, short events, void *data);

void on_timer(int fd, short events, void *data);

SSL_CTX *ssl_ctx_init(char *ca, char *cert, char *key, char *passwd, char *cipher, int verify);

void ssl_ctx_exit(SSL_CTX *ctx);

void service_worker_process(void *data);

#endif
