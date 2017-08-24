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

    if(strncasecmp(level, "crit", 4) == 0)
        return LOG_LEVEL_CRIT;
    else if(strncasecmp(level, "err", 3) == 0)
        return LOG_LEVEL_ERR;
    else if(strncasecmp(level, "warning", 7) == 0)
        return LOG_LEVEL_WARNING;
    else if(strncasecmp(level, "notice", 6) == 0)
        return LOG_LEVEL_NOTICE;
    else if(strncasecmp(level, "info", 4) == 0)
        return LOG_LEVEL_INFO;
    else if(strncasecmp(level, "debug", 5) == 0)
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
