#ifndef __PROCESS_H__
#define __PROCESS_H__

typedef void (*proc_cb_t)(void *);

pid_t service_proc_fork(proc_cb_t cb, void *data);

int service_proc_kill(pid_t pid, int sig);

void service_proc_wait();

#endif
