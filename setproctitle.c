#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include "setproctitle.h"

int os_argc = 0;
char **os_argv = NULL;

extern char **environ;

char* os_setproctitle(int argc, char *argv[], char *fmt, ...)
{
    int i = 0;
    int size = 0;
    char *p = NULL, *env = NULL;
    char *last_argv = NULL;
    char title[MAX_TITLE_SIZE] = {0};

    va_list ap;
    va_start(ap, fmt);
    vsprintf(title, fmt, ap);
    va_end(ap);

    for(i = 0; environ[i]; i++) {
        size += strlen(environ[i]) + 1;
    }

    env = p = (char*)malloc(size);
    if(p == NULL)
        return NULL;

    last_argv = argv[0];
    for(i = 0; argv[i]; i++) {
        if(last_argv == argv[i]) {
            last_argv = argv[i] + strlen(argv[i]) + 1;
        }
    }

    for(i = 0; environ[i]; i++) {
        if(last_argv == environ[i]) {
            size = strlen(environ[i]) + 1;
            last_argv = environ[i] + size;

            strncpy(p, environ[i], size);
            environ[i] = p;
            p += size;
        }
    }
    last_argv--;

    strncpy(argv[0], title, last_argv - argv[0]);
    p = argv[0] + strlen(argv[0]) + 1;
    if(last_argv - p > 0) {
        memset(p, 0, last_argv - p);
    }

    return env;
}
