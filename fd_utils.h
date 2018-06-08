#ifndef __FD_UTILS_H__
#define __FD_UTILS_H__

#define MAX_FD_NUM 256

void set_sock_option(int fd);

int fd_pair(int fd[2]);

int fd_send(int sockfd, int fd, int option);

int fd_recv(int sockfd, int *fd, int *option);

int fds_send(int sockfd, int fds[], int num, int option);

int fds_recv(int sockfd, int fds[], int *num, int *option);

void fd_close(int fd);

#endif
