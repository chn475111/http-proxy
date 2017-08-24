#created by lijk<lijk@infosec.com.cn>
CC := cc
CFLAGS := -g -O0 -Wall -fPIC
CFLAGS += -D_HTTP
CFLAGS += -D_DEBUG
CFLAGS += -DINI_HANDLER_LINENO
CFLAGS += -I./
CFLAGS += -I./include/
LDFLAGS := -L./
LDFLAGS += -L./lib/ -lssl -lcrypto -levent
LIBS := -ldl -lrt

.PHONY : default all clean

SRCS += rbtree.c timer.c timer_handler.c ini.c ini_handler.c http_parser.c http_handler.c
SRCS += utils.c file_utils.c cert_utils.c ssl_utils.c tcp_utils.c
SRCS += log.c options.c signals.c base64.c passwd.c crypto_lock.c
SRCS += event_handler.c proc.c worker.c master.c main.c

OBJS = $(SRCS:.c=.o)

TARGET = http-proxy

default : all

all : ${TARGET}

${TARGET} : ${OBJS}
	${CC} -o $@ ${OBJS} ${LDFLAGS} ${LIBS}
	@echo "$@"

%.o : %.c %.h
	${CC} ${CFLAGS} -o $@ -c $<

clean :
	rm -rf ${OBJS} ${TARGET}
