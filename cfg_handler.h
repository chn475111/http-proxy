#ifndef __CFG_HANDLER_H__
#define __CFG_HANDLER_H__

#include <stdbool.h>
#include <libconfig.h>

#define MAX_PROCESS_NUM 16
#define MAX_CRED_NUM 256
#define MAX_BACKEND_NUM 256
#define MAX_SERVER_NUM 256

//全局变量
typedef struct global_s
{
    char *version;                                                  //服务版本
    char *level;                                                    //日志级别: crit, err, warning, notice, info, debug
    int number;                                                     //进程/内核: [1, 16]
    int timeout;                                                    //连接超时: 默认30秒
}global_t;

//可信配置
typedef struct cred_s
{
    char *name;                                                     //可信名称

    char *ca;                                                       //CA根证书
    char *cert;                                                     //公钥证书
    char *key;                                                      //私钥证书
    char *passwd;                                                   //私钥口令
    char *cipher;                                                   //密码条件
    bool verify;                                                    //是否校验对端证书
}cred_t;

//后台服务器
typedef struct backend_s
{
    char *backendName;                                              //后台服务器名称

    char *backendIP;                                                //后台服务器地址
    unsigned short backendPort;                                     //后台服务器端口
}backend_t;

//本地服务
typedef struct server_s
{
    bool isEnable;                                                  //本地服务是否启用
    char *proxyType;                                                //本地服务代理类型: tcp/http
    char *serverName;                                               //本地服务名称

    char *credName;                                                 //可信配置名称
    cred_t *cred;                                                   //可信配置地址

    char *backendName;                                              //后台服务器名称
    backend_t *backend;                                             //后台服务器地址

    char *serverIP;                                                 //本地服务监听地址
    unsigned short serverPort;                                      //本地服务监听端口
}server_t;

typedef struct proxy_s
{
    config_t cfg;                                                   //配置文件
    global_t global;                                                //全局变量

    int credNumber;                                                 //可信配置个数
    cred_t credArray[MAX_CRED_NUM];                                 //可信配置数组

    int backendNumber;                                              //后台服务器个数
    backend_t backendArray[MAX_BACKEND_NUM];                        //后台服务器数组

    int serverNumber;                                               //本地服务个数
    server_t serverArray[MAX_SERVER_NUM];                           //本地服务数组
}proxy_t;

int cfg_init(proxy_t *proxy, const char *filename);

void cfg_exit(proxy_t *proxy);

#endif
