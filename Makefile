#created by lijk<lijk@infosec.com.cn>
CC := gcc
CFLAGS := -g -O0 -Wall -fPIC
CFLAGS += -D__DEBUG__
CFLAGS += -I./
CFLAGS += -I./include/
LDFLAGS := -L./
LDFLAGS += -L./lib/ -lconfig -levent -lssl -lcrypto
LIBS := -lrt -ldl

.PHONY : default all clean

SRCS += log.c utils.c file_utils.c cert_utils.c fd_utils.c tcp_utils.c membuf.c
SRCS += hashtable.c http_parser.c cfg_handler.c http_handler.c event_handler.c
SRCS += options.c signals.c setproctitle.c process.c worker.c master.c main.c

OBJS = $(SRCS:.c=.o)

TARGET = proxy

default : all

all : ${TARGET}

${TARGET} : ${OBJS}
	${CC} -o $@ ${OBJS} ${LDFLAGS} ${LIBS}
	@echo "$@"

%.o : %.c %.h
	${CC} ${CFLAGS} -o $@ -c $<

clean :
	rm -rf ${OBJS} ${TARGET}
