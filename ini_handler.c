#include <stdlib.h>
#include <string.h>
#include "log.h"
#include "ini_handler.h"

int config_handler(void *user, const char *section, const char *name, const char *value, int lineno)
{
    int loop = 0;
    config_t *conf = (config_t*)user;

    log_info("[lineno:%d] - [%s] %s = %s", lineno, section, name, value);

    if(strcasecmp(section, "global") == 0 && strcasecmp(name, "ca") == 0)
        conf->ca = strdup(value);
    if(strcasecmp(section, "global") == 0 && strcasecmp(name, "crl") == 0)
        conf->crl = strdup(value);

    if(strcasecmp(section, "log") == 0 && strcasecmp(name, "level") == 0)
        conf->level = strdup(value);

    if(strcasecmp(section, "server") == 0 && strcasecmp(name, "count") == 0)
        conf->count = strtol(value, NULL, 0);
    for(loop = 0;  loop < conf->count; loop ++)
    {
        char sec[4096+1];
        snprintf(sec, 4096+1, "server%d", loop);

        if(strcasecmp(section, sec) == 0 && strcasecmp(name, "serverName") == 0)
            conf->ctrl[loop].serverName = strdup(value);
        else if(strcasecmp(section, sec) == 0 && strcasecmp(name, "isEnable") == 0)
            conf->ctrl[loop].isEnable = strtol(value, NULL, 0);
        else if(strcasecmp(section, sec) == 0 && strcasecmp(name, "isReqDirect") == 0)
            conf->ctrl[loop].isReqDirect = strtol(value, NULL, 0);
        else if(strcasecmp(section, sec) == 0 && strcasecmp(name, "isResDirect") == 0)
            conf->ctrl[loop].isResDirect = strtol(value, NULL, 0);
        else if(strcasecmp(section, sec) == 0 && strcasecmp(name, "server_ip") == 0)
            conf->addr[loop].server_ip = strdup(value);
        else if(strcasecmp(section, sec) == 0 && strcasecmp(name, "server_port") == 0)
            conf->addr[loop].server_port = atoi(value);
        else if(strcasecmp(section, sec) == 0 && strcasecmp(name, "backend_ip") == 0)
            conf->addr[loop].backend_ip = strdup(value);
        else if(strcasecmp(section, sec) == 0 && strcasecmp(name, "backend_port") == 0)
            conf->addr[loop].backend_port = atoi(value);
        else if(strcasecmp(section, sec) == 0 && strcasecmp(name, "ca") == 0)
            conf->ssl[loop].ca = strdup(value);
        else if(strcasecmp(section, sec) == 0 && strcasecmp(name, "crl") == 0)
            conf->ssl[loop].crl = strdup(value);
        else if(strcasecmp(section, sec) == 0 && strcasecmp(name, "cert") == 0)
            conf->ssl[loop].cert = strdup(value);
        else if(strcasecmp(section, sec) == 0 && strcasecmp(name, "key") == 0)
            conf->ssl[loop].key = strdup(value);
        else if(strcasecmp(section, sec) == 0 && strcasecmp(name, "enccert") == 0)
            conf->ssl[loop].enccert = strdup(value);
        else if(strcasecmp(section, sec) == 0 && strcasecmp(name, "enckey") == 0)
            conf->ssl[loop].enckey = strdup(value);
        else if(strcasecmp(section, sec) == 0 && strcasecmp(name, "sigcert") == 0)
            conf->ssl[loop].sigcert = strdup(value);
        else if(strcasecmp(section, sec) == 0 && strcasecmp(name, "sigkey") == 0)
            conf->ssl[loop].sigkey = strdup(value);
        else if(strcasecmp(section, sec) == 0 && strcasecmp(name, "passwd") == 0)
            conf->ssl[loop].passwd = strdup(value);
        else if(strcasecmp(section, sec) == 0 && strcasecmp(name, "cipher") == 0)
            conf->ssl[loop].cipher = strdup(value);
        else if(strcasecmp(section, sec) == 0 && strcasecmp(name, "isVerify") == 0)
            conf->ssl[loop].isVerify = strtol(value, NULL, 0);
        else
            continue;
    }

    return 1;
}

void config_free(void *user)
{
    int loop = 0;
    config_t *conf = (config_t*)user;

    if(conf->ca) free(conf->ca);
    if(conf->crl) free(conf->crl);

    if(conf->level) free(conf->level);

    for(loop = 0;  loop < conf->count; loop ++)
    {
        if(conf->ctrl[loop].serverName) free(conf->ctrl[loop].serverName);
        if(conf->addr[loop].server_ip) free(conf->addr[loop].server_ip);
        if(conf->addr[loop].backend_ip) free(conf->addr[loop].backend_ip);
        if(conf->ssl[loop].ca) free(conf->ssl[loop].ca);
        if(conf->ssl[loop].crl) free(conf->ssl[loop].crl);
        if(conf->ssl[loop].cert) free(conf->ssl[loop].cert);
        if(conf->ssl[loop].key) free(conf->ssl[loop].key);
        if(conf->ssl[loop].enccert) free(conf->ssl[loop].enccert);
        if(conf->ssl[loop].enckey) free(conf->ssl[loop].enckey);
        if(conf->ssl[loop].sigcert) free(conf->ssl[loop].sigcert);
        if(conf->ssl[loop].sigkey) free(conf->ssl[loop].sigkey);
        if(conf->ssl[loop].passwd) free(conf->ssl[loop].passwd);
        if(conf->ssl[loop].cipher) free(conf->ssl[loop].cipher);
    }
}
