#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "log.h"
#include "proc.h"

pid_t service_fork_proc(proc_cb_t cb, void *data)
{
    pid_t pid = fork();
    switch(pid)
    {
        case -1:
            log_err("fork failed - %d: %s", errno, strerror(errno));
            break;
        case 0:
            cb(data);   //exit();
            break;
        default:
            log_debug("fork succeed - child pid: %d", pid);
            break;
    }
    return pid;
}

void service_wait_proc()
{
    pid_t pid;
    int status;
    do{
        pid = waitpid(-1, &status, WNOHANG);
        switch(pid)
        {
            case -1:
                if(errno == EINTR)
                    continue;
                if(errno != ECHILD)
                    log_err("waitpid failed - %d: %s", errno, strerror(errno));
                break;
            case 0:
                usleep(100);
                break;
            default:
                log_debug("waitpid succeed - child pid: %d", pid);
                break;
        }
    }while(pid >= 0);
}
