#ifndef __INI_HANDLER_H__
#define __INI_HANDLER_H__

#define MAX_COUNT_NUM 4096

typedef struct ctrl_s
{
    char *serverName;                   //服务名称
    int isEnable;                       //服务状态: 0, 1
    int isReqDirect;                    //请求重定向: 0, 1
    int isResDirect;                    //响应重定向: 0, 1
}ctrl_t;

typedef struct addr_s
{
    char *server_ip;                    //服务地址IP
    unsigned short server_port;         //服务端口PORT
    char *backend_ip;                   //后台地址IP
    unsigned short backend_port;        //后台端口PORT
}addr_t;

typedef struct ssl_s
{
    char *ca;                           //CA证书
    char *crl;                          //CRL证书
    char *cert;                         //RSA证书
    char *key;                          //RSA私钥
    char *enccert;                      //SM2加密证书
    char *enckey;                       //SM2加密私钥
    char *sigcert;                      //SM2签名证书
    char *sigkey;                       //SM2签名私钥
    char *passwd;                       //RSA和SM2私钥口令
    char *cipher;                       //密码套件
    int isVerify;                       //验证类型: 0, 1
}ssl_t;

typedef struct config_s
{
    char *ca;                           //CA证书合集
    char *crl;                          //CRL证书合集
    char *level;                        //日志级别: crit, err, warning, notice, info, debug

    int count;                          //服务计数: [1, 4096]
    ctrl_t ctrl[MAX_COUNT_NUM];
    addr_t addr[MAX_COUNT_NUM];
    ssl_t ssl[MAX_COUNT_NUM];
}config_t;

int config_handler(void *user, const char *section, const char *name, const char *value, int lineno);

void config_free(void *user);

#endif
