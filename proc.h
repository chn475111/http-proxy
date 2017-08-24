#ifndef __PROC_H__
#define __PROC_H__

typedef void (*proc_cb_t)(void *);

#ifdef __cplusplus
extern "C" {
#endif

pid_t service_fork_proc(proc_cb_t cb, void *data);

void service_wait_proc();

#ifdef __cplusplus
}
#endif

#endif
