#include "log.h"

enum log_level _log_level = LOG_LEVEL_INFO;

void log_open(const char *ident, bool tostderr)
{
    int option = LOG_CONS | LOG_PID;
    int facility = LOG_USER;

    if (tostderr) option |= LOG_PERROR;

    openlog(ident, option, facility);
}

// level: crit, err, warning, notice, info, debug
enum log_level log_get_level(const char *level)
{
    if(level == NULL)
        return LOG_LEVEL_INFO;

    if(strcasecmp(level, "crit") == 0)
        return LOG_LEVEL_CRIT;
    else if(strcasecmp(level, "err") == 0)
        return LOG_LEVEL_ERR;
    else if(strcasecmp(level, "warning") == 0)
        return LOG_LEVEL_WARNING;
    else if(strcasecmp(level, "notice") == 0)
        return LOG_LEVEL_NOTICE;
    else if(strcasecmp(level, "info") == 0)
        return LOG_LEVEL_INFO;
    else if(strcasecmp(level, "debug") == 0)
        return LOG_LEVEL_DEBUG;
    else
        return LOG_LEVEL_INFO;
}

void log_set_level(enum log_level level)
{
    _log_level = level;
}

void log_close(void)
{
    closelog();
}
