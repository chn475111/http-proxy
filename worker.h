#ifndef __WORKER_H__
#define __WORKER_H__

#include "list.h"
#include "ini_handler.h"
#include "connection.h"

typedef struct worker_s
{
    SSL_CTX *ctx[MAX_COUNT_NUM];            //SSL_CTX句柄数组
    connection_t conn[MAX_CONN_NUM];        //Connection连接数组
    timer_root_t timer;                     //Timer根节点
    struct event ev_timer;                  //计时器事件
    struct master_s *mast;                  //Master句柄
    struct event_base *base;                //Base事件句柄
    struct list_head list;                  //List头节点 (用来向客户端群发通知消息)
}worker_t;

SSL_CTX *ssl_ctx_init(char *ca, char *crl, char *cert, char *key, \
    char *enccert, char *enckey, char *sigcert, char *sigkey, char *passwd, char *cipher, int verify);

void ssl_ctx_exit(SSL_CTX *ctx);

void service_worker_process(void *data);

#endif
