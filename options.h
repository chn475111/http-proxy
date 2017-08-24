#ifndef __OPTIONS_H__
#define __OPTIONS_H__

#include <stdbool.h>

#define VERSION "0.0.1"

extern char *config;
extern bool daemonize;

void options_parse(int argc, char *argv[]);

#endif
