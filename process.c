#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "log.h"
#include "process.h"

pid_t service_proc_fork(proc_cb_t cb, void *data)
{
    pid_t pid = fork();
    switch(pid)
    {
        case -1:
            log_err("fork failed - %d: %s", errno, strerror(errno));
            break;
        case 0:
            cb(data);
            exit(0);
        default:
            log_debug("fork succeed - child pid: %d", pid);
            break;
    }
    return pid;
}

int service_proc_kill(pid_t pid, int sig)
{
    return kill(pid, sig);
}

void service_proc_wait()
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
