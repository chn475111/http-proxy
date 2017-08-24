#ifndef __TIMER_HANDLER_H__
#define __TIMER_HANDLER_H__

#define TIMEOUT 30*1000*1000    //连接30秒超时

long long get_local_time();

void timer_node_free(void *data);

#endif
