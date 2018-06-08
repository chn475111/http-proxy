#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "membuf.h"

membuf_t* membuf_new(int size)
{
    membuf_t *h = (membuf_t*)malloc(sizeof(membuf_t));
    if(h == NULL)
    {
        fprintf(stderr, "%s %s:%u - %d: %s\n", __FUNCTION__, __FILE__, __LINE__, errno, strerror(errno));
        return NULL;
    }
    memset(h, 0, sizeof(membuf_t));

    if(size > 0)
    {
        h->length = size;
        h->buffer = (unsigned char*)malloc(size + 1);
        if(h->buffer == NULL)
        {
            fprintf(stderr, "%s %s:%u - %d: %s\n", __FUNCTION__, __FILE__, __LINE__, errno, strerror(errno));
            goto ErrP;
        }
        memset(h->buffer, 0, size + 1);
    }

    h->mlen = 0;
    h->mpos = h->buffer;
    return h;
ErrP:
    if(h) membuf_delete(h);
    return NULL;
}

void membuf_delete(membuf_t *h)
{
    if(h)
    {
        h->length = 0;
        if(h->buffer)
        {
            free(h->buffer);
            h->buffer = NULL;
        }
        h->mlen = 0;
        h->mpos = NULL;
        free(h);
    }
}
