#ifndef __TCP_UTILS_H__
#define __TCP_UTILS_H__

void set_socket_option(int fd);

int tcp_socket();

int tcp_bind(int fd, char *ip, unsigned short port);

int tcp_listen(int fd, int backlog);

int tcp_accept(int sockfd, char *ip, int iplen, unsigned short *port);

int tcp_connect(int fd, char *ip, unsigned short port);

int tcp_send(int fd, char *buf, int len);

int tcp_recv(int fd, char *buf, int len);

void tcp_close(int fd);

#endif
