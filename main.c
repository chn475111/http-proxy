#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include "log.h"
#include "options.h"
#include "master.h"

int main(int argc, char *argv[])
{
    int ret = 0;
    char *name = basename(argv[0]);

    options_parse(argc, argv);
    if(daemonize) daemon(1, 0);

    log_open(name, !daemonize);
    ret = service_master_process(config);
    log_close();

    exit(ret);
}
