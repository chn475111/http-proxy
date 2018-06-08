#include "log.h"
#include "cfg_handler.h"

int cfg_init(proxy_t *proxy, const char *filename)
{
    int ret = CONFIG_TRUE;
    int i = 0, j = 0;
    config_t *cfg = NULL;
    config_setting_t *setting = NULL;
    config_setting_t *elem = NULL;

    cfg = &proxy->cfg;
    config_init(cfg);

    ret = config_read_file(cfg, filename);
    if(ret == CONFIG_FALSE)
    {
        log_err("config_read_file failed [ %s : %d ] - %s\n", config_error_file(cfg), config_error_line(cfg), config_error_text(cfg));
        goto ErrP;
    }
    /* config_write_file(cfg, filename); */

    config_lookup_string(cfg, "version", (const char**)&proxy->global.version);

    setting = config_lookup(cfg, "log");
    config_setting_lookup_string(setting, "level", (const char**)&proxy->global.level);

    setting = config_lookup(cfg, "process");
    config_setting_lookup_int(setting, "number", (int*)&proxy->global.number);
    if(proxy->global.number <= 0) proxy->global.number = 1;
    if(proxy->global.number > MAX_PROCESS_NUM) proxy->global.number = MAX_PROCESS_NUM;

    setting = config_lookup(cfg, "connection");
    config_setting_lookup_int(setting, "timeout", (int*)&proxy->global.timeout);
    if(proxy->global.timeout <= 0) proxy->global.timeout = 30;

    setting = config_lookup(cfg, "cred");
    proxy->credNumber = config_setting_length(setting);

    if(proxy->credNumber > MAX_CRED_NUM) proxy->credNumber = MAX_CRED_NUM;
    for(i = 0; i < proxy->credNumber; i++)
    {
        elem = config_setting_get_elem(setting, i);
        config_setting_lookup_string(elem, "name", (const char**)&proxy->credArray[i].name);
        config_setting_lookup_string(elem, "ca", (const char**)&proxy->credArray[i].ca);
        config_setting_lookup_string(elem, "cert", (const char**)&proxy->credArray[i].cert);
        config_setting_lookup_string(elem, "key", (const char**)&proxy->credArray[i].key);
        config_setting_lookup_string(elem, "passwd", (const char**)&proxy->credArray[i].passwd);
        config_setting_lookup_string(elem, "cipher", (const char**)&proxy->credArray[i].cipher);
        config_setting_lookup_bool(elem, "verify", (int*)&proxy->credArray[i].verify);
    }

    setting = config_lookup(cfg, "backend");
    proxy->backendNumber = config_setting_length(setting);

    if(proxy->backendNumber > MAX_BACKEND_NUM) proxy->backendNumber = MAX_BACKEND_NUM;
    for(i = 0; i < proxy->backendNumber; i++)
    {
        elem = config_setting_get_elem(setting, i);
        config_setting_lookup_string(elem, "backendName", (const char**)&proxy->backendArray[i].backendName);
        config_setting_lookup_string(elem, "backendIP", (const char**)&proxy->backendArray[i].backendIP);
        config_setting_lookup_int(elem, "backendPort", (int*)&proxy->backendArray[i].backendPort);
    }

    setting = config_lookup(cfg, "server");
    proxy->serverNumber = config_setting_length(setting);

    if(proxy->serverNumber > MAX_SERVER_NUM) proxy->serverNumber = MAX_SERVER_NUM;
    for(i = 0; i < proxy->serverNumber; i++)
    {
        elem = config_setting_get_elem(setting, i);
        config_setting_lookup_bool(elem, "isEnable", (int*)&proxy->serverArray[i].isEnable);
        config_setting_lookup_string(elem, "proxyType", (const char**)&proxy->serverArray[i].proxyType);
        config_setting_lookup_string(elem, "serverName", (const char**)&proxy->serverArray[i].serverName);
        config_setting_lookup_string(elem, "credName", (const char**)&proxy->serverArray[i].credName);
        config_setting_lookup_string(elem, "backendName", (const char**)&proxy->serverArray[i].backendName);
        config_setting_lookup_string(elem, "serverIP", (const char**)&proxy->serverArray[i].serverIP);
        config_setting_lookup_int(elem, "serverPort", (int*)&proxy->serverArray[i].serverPort);

        proxy->serverArray[i].cred = NULL;
        for(j = 0; j < proxy->credNumber; j++)
        {
            if(strcasecmp(proxy->serverArray[i].credName, proxy->credArray[j].name) == 0)
            {
                proxy->serverArray[i].cred = &proxy->credArray[j];
                break;
            }
        }
        if(proxy->serverArray[i].cred == NULL)
        {
            log_err("\"%s\" find cred by \"%s\" failed", proxy->serverArray[i].serverName, proxy->serverArray[i].credName);
            goto ErrP;
        }

        proxy->serverArray[i].backend = NULL;
        for(j = 0; j < proxy->backendNumber; j++)
        {
            if(strcasecmp(proxy->serverArray[i].backendName, proxy->backendArray[j].backendName) == 0)
            {
                proxy->serverArray[i].backend = &proxy->backendArray[j];
                break;
            }
        }
        if(proxy->serverArray[i].backend == NULL)
        {
            log_err("\"%s\" find backend by \"%s\" failed", proxy->serverArray[i].serverName, proxy->serverArray[i].backendName);
            goto ErrP;
        }
    }

    return 0;
ErrP:
    cfg_exit(proxy);
    return -1;
}

void cfg_exit(proxy_t *proxy)
{
    if(proxy) config_destroy(&proxy->cfg);
}
