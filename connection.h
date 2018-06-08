#ifndef __CONNECTION_H__
#define __CONNECTION_H__

#include <event.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "list.h"
#include "uthash.h"
#include "membuf.h"
#include "http_handler.h"

#define MAX_IP_SIZE 16
#define MAX_CONN_NUM 65536

typedef struct connection_s
{
    int slot;                               //FD索引
    int fd;                                 //FD句柄
    SSL *ssl;                               //SSL句柄
    char ip[MAX_IP_SIZE];                   //IP地址
    unsigned short port;                    //Port端口
    http_t *http;                           //HTTP数据
    membuf_t *membuf;                       //Mem缓存
    struct event event;                     //Event事件
    UT_hash_handle hash;                    //Hash节点
    struct list_head list;                  //List节点
    struct connection_s *peer;              //Connection对端节点
}connection_t;

#endif
