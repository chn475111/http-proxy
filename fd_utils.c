#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "fd_utils.h"

void set_sock_option(int fd)
{
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
}

int fd_pair(int fd[2])
{
    int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
    if(ret < 0)
        return ret;

    set_sock_option(fd[0]);
    set_sock_option(fd[1]);
    return ret;
}

int fd_send(int sockfd, int fd, int option)
{
    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    char ctrl[CMSG_SPACE(1*sizeof(int))];
    memset(ctrl, 0, CMSG_SPACE(1*sizeof(int)));

    iov.iov_base = (char*)&option;
    iov.iov_len = sizeof(int);

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctrl;
    msg.msg_controllen = CMSG_SPACE(1*sizeof(int));
    msg.msg_flags = 0;

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len = CMSG_LEN(1*sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;

    ((int*)CMSG_DATA(cmsg))[0] = fd;

    return sendmsg(sockfd, &msg, 0);
}

int fd_recv(int sockfd, int *fd, int *option)
{
    int ret;
    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    char ctrl[CMSG_SPACE(1*sizeof(int))];
    memset(ctrl, 0, CMSG_SPACE(1*sizeof(int)));

    iov.iov_base = (char*)option;
    iov.iov_len = sizeof(int);

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctrl;
    msg.msg_controllen = CMSG_SPACE(1*sizeof(int));
    msg.msg_flags = 0;

    if((ret = recvmsg(sockfd, &msg, 0)) <= 0)
        return ret;

    cmsg = CMSG_FIRSTHDR(&msg);
    *fd = ((int*)CMSG_DATA(cmsg))[0];

    return ret;
}

int fds_send(int sockfd, int fds[], int num, int option)
{
    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    char ctrl[CMSG_SPACE(MAX_FD_NUM*sizeof(int))];
    memset(ctrl, 0, CMSG_SPACE(MAX_FD_NUM*sizeof(int)));
    int i;

    iov.iov_base = (char*)&option;
    iov.iov_len = sizeof(int);

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctrl;
    msg.msg_controllen = CMSG_SPACE(num*sizeof(int));
    msg.msg_flags = 0;

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len = CMSG_LEN(num*sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;

    for(i = 0; i < num; i++)
        ((int*)CMSG_DATA(cmsg))[i] = fds[i];

    return sendmsg(sockfd, &msg, 0);
}

int fds_recv(int sockfd, int fds[], int *num, int *option)
{
    int ret;
    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    char ctrl[CMSG_SPACE(MAX_FD_NUM*sizeof(int))];
    memset(ctrl, 0, CMSG_SPACE(MAX_FD_NUM*sizeof(int)));
    int i;

    iov.iov_base = (char*)option;
    iov.iov_len = sizeof(int);

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctrl;
    msg.msg_controllen = CMSG_SPACE(*num*sizeof(int));
    msg.msg_flags = 0;

    if((ret = recvmsg(sockfd, &msg, 0)) <= 0)
        return ret;

    cmsg = CMSG_FIRSTHDR(&msg);
    *num = (cmsg->cmsg_len-sizeof(struct cmsghdr))/sizeof(int);
    for(i = 0; i < *num; i++)
        fds[i] = ((int*)CMSG_DATA(cmsg))[i];

    return ret;
}

void fd_close(int fd)
{
    if(fd > 0) close(fd);
}
