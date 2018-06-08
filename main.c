#include <stdlib.h>
#include <unistd.h>
#include "log.h"
#include "options.h"
#include "setproctitle.h"
#include "master.h"

int main(int argc, char *argv[])
{
    os_argc = argc;
    os_argv = argv;

    options_parse(argc, argv);
    if(daemonize) daemon(1, 0);

    log_open("proxy", !daemonize);
    int ret = service_master_process(NULL);
    log_close();

    exit(ret);
}
