#ifndef __SIGNALS_H__
#define __SIGNALS_H__

#include <signal.h>

#ifndef likely
#define likely(x)   __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

extern volatile sig_atomic_t isterm;    // 结束信号
extern volatile sig_atomic_t isalarm;   // 时钟信号(1秒1次)

void signals_register();

#endif
