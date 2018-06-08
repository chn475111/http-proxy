#ifndef __MEMBUF_H__
#define __MEMBUF_H__

#define MAX_DATA_SIZE 4096

typedef struct membuf_s
{
    int mlen;                   //动态长度
    unsigned char *mpos;        //动态指针

    int length;                 //缓存长度
    unsigned char *buffer;      //缓存指针
}membuf_t;

membuf_t* membuf_new(int size);

void membuf_delete(membuf_t *h);

#endif
