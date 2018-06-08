#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "utils.h"

int get_proc_num()
{
    return sysconf(_SC_NPROCESSORS_ONLN);
}

int set_proc_priority(int prio)
{
    return setpriority(PRIO_PROCESS, 0, prio);
}

int set_proc_affinity(int id)
{
    cpu_set_t mask;

    CPU_ZERO(&mask);
    CPU_SET(id, &mask);
    return sched_setaffinity(0, sizeof(mask), &mask);
}

int set_conn_limit(unsigned max)
{
    struct rlimit rl;

    rl.rlim_cur = max;
    rl.rlim_max = max;
    return setrlimit(RLIMIT_NOFILE, &rl);
}
