#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

void set_socket_option(int fd)
{
    struct timeval tv = {
        .tv_sec = 3,
        .tv_usec = 0
    };
    fcntl(fd, F_SETFD, fcntl(fd, F_GETFL) | FD_CLOEXEC);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(struct timeval));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));
}

int tcp_socket()
{
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(fd == -1)
        return -1;

    set_socket_option(fd);
    return fd;
}

int tcp_bind(int fd, char *ip, unsigned short port)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(struct sockaddr_in));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip);
    addr.sin_port = htons(port);

    int flag = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void*)&flag, sizeof(int));
    return bind(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
}

int tcp_listen(int fd, int backlog)
{
    return listen(fd, backlog);
}

int tcp_accept(int sockfd, char *ip, int iplen, unsigned short *port)
{
    int fd = 0;
    int len = sizeof(struct sockaddr_in);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(struct sockaddr_in));

    do{
        fd = accept(sockfd, (struct sockaddr *)&addr, (socklen_t*)&len);
        if(fd != -1 || errno != EAGAIN)
            break;
    }while(0);
    if(fd == -1)
        return -1;

    if(ip && iplen>0) snprintf(ip, iplen, "%s", inet_ntoa(addr.sin_addr));
    if(port) *port = ntohs(addr.sin_port);

    set_socket_option(fd);
    return fd;
}

int tcp_connect(int fd, char *ip, unsigned short port)
{
    int ret = 0;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(struct sockaddr_in));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip);
    addr.sin_port = htons(port);

    do{
        ret = connect(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
        if(ret != -1 || errno != EINPROGRESS)
            break;
    }while(0);

    return ret;
}

int tcp_send(int fd, char *buf, int len)
{
    int send_len = 0, send_tmp = 0;

    do{
        send_tmp = send(fd, buf+send_len, len-send_len, 0);
        if(send_tmp == -1)
        {
            if(errno == EINTR || errno == EAGAIN)
                break;
            return -1;
        }
        send_len += send_tmp; 
    }while(0);

    return send_len;
}

int tcp_recv(int fd, char *buf, int len)
{
    int recv_len = 0, recv_tmp = 0;

    do{
        recv_tmp = recv(fd, buf+recv_len, len-recv_len, 0);
        if(recv_tmp == 0)
            return 0;
        else if(recv_tmp == -1)
        {
            if(errno == EINTR || errno == EAGAIN)
                break;
            return -1;
        }
        else
            recv_len += recv_tmp;
    }while(0);

    return recv_len;
}

void tcp_close(int fd)
{
    if(fd > 0) close(fd);
}
