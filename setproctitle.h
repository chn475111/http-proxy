#ifndef __SETPROCTITLE_H__
#define __SETPROCTITLE_H__

#define MAX_TITLE_SIZE 2048

extern int os_argc;
extern char **os_argv;

char* os_setproctitle(int argc, char *argv[], char *fmt, ...);

#endif
