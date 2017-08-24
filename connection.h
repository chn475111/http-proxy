#ifndef __CONNECTION_H__
#define __CONNECTION_H__

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <event.h>
#include "rbtree.h"
#include "timer.h"
#include "list.h"
#include "ini_handler.h"
#include "http_handler.h"

#define MAX_CONN_NUM 65536

typedef struct connection_s
{
    int slot;                               //FD索引
    int fd;                                 //FD句柄
    SSL *ssl;                               //SSL句柄
    char *ip;                               //IP地址
    unsigned short port;                    //PORT端口
    http_t *http;                           //HTTP句柄
    timer_node_t timer;                     //Timer节点
    struct event event;                     //Event事件
    struct connection_s *peer;              //对端节点
    struct list_head list;                  //List节点 (用来向客户端群发通知消息)
}connection_t;

#endif
