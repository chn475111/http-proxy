#include "signals.h"

volatile sig_atomic_t isterm = 0;   // 结束信号
volatile sig_atomic_t isalarm = 0;  // 时钟信号(1秒1次)

void signals_register()
{
    signal(SIGHUP, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGALRM, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGSYS, SIG_IGN);
}
