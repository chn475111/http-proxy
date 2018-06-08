#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <getopt.h>
#include "options.h"

char *config = "proxy.cfg";
bool daemonize = false;

static void print_usage(char *name)
{
    fprintf(stdout, "%s - version %s (build at %s %s)\n", name, VERSION, __DATE__, __TIME__);
    fprintf(stdout, "Usage:\n");
    fprintf(stdout, "   -c, --config        set configuration file (default: %s)\n", config);
    fprintf(stdout, "   -d, --daemon        set server daemonize\n");
    fprintf(stdout, "   -v, --version       print version message\n");
    fprintf(stdout, "   -h, --help          print help message\n");
}

void options_parse(int argc, char *argv[])
{
    int ch = 0;
    int longindex = 0;
    char *optstring = "c:dvh?";
    struct option longopts[] = {
        {"config", required_argument, NULL, 'c'},
        {"daemon", no_argument, NULL, 'd'},
        {"version", no_argument, NULL, 'v'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    char *name = basename(argv[0]);

    opterr = 1;
    while((ch = getopt_long(argc, argv, optstring, longopts, &longindex)) != -1)
    {
        switch(ch)
        {
            case 'c':
                config = optarg;
                break;
            case 'd':
                daemonize = true;
                break;
            case 'v':
                print_usage(name);
                exit(EXIT_SUCCESS);
                break;
            case 'h':
                print_usage(name);
                exit(EXIT_SUCCESS);
                break;
            default:
                print_usage(name);
                exit(EXIT_FAILURE);
                break;
        }
    }

    argc -= optind;
    argv += optind;
}
