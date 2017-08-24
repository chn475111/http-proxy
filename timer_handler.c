#include <string.h>
#include <sys/time.h>
#include "worker.h"
#include "connection.h"
#include "event_handler.h"
#include "timer_handler.h"

long long get_local_time()
{
    struct timeval tv;
    memset(&tv, 0, sizeof(struct timeval));

    gettimeofday(&tv, NULL);
    return tv.tv_sec*1000*1000LL + tv.tv_usec;
}

void timer_node_free(void *data)
{
    if(data == NULL)
        return;

    connection_t *conn = (connection_t*)data;
    connection_t *peer =  conn->peer;

    worker_t *work = (worker_t*)container_of((void*)(conn-conn->fd), worker_t, conn);

    event_conn_free(work, conn);
    event_conn_free(work, peer);
}
