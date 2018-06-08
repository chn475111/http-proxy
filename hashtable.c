#include "log.h"
#include "hashtable.h"

static int hash_cmp(connection_t *a, connection_t *b)
{
    return a->fd - b->fd;
}

void hash_create(connection_t **head)
{
    *head = NULL;
}

void hash_add(connection_t **head, connection_t *conn)
{
    HASH_ADD(hash, *head, fd, sizeof(int), conn);
}

void hash_del(connection_t **head, connection_t *conn)
{
    HASH_DELETE(hash, *head, conn);
}

connection_t* hash_find(connection_t **head, int fd)
{
    connection_t *ptr = NULL;
    HASH_FIND(hash, *head, &fd, sizeof(int), ptr);
    return ptr;
}

unsigned int hash_count(connection_t **head)
{
    return HASH_CNT(hash, *head);
}

void hash_sort(connection_t **head)
{
    HASH_SRT(hash, *head, hash_cmp);
}

void hash_dump(connection_t **head)
{
    connection_t *tmp = NULL;
    connection_t *ptr = NULL;
    HASH_ITER(hash, *head, ptr, tmp)
    {
        log_debug("fd \"%d\" - \"%s:%hu\"", ptr->fd, ptr->ip, ptr->port);
    }
}

void hash_destroy(connection_t **head)
{
    HASH_CLEAR(hash, *head);
}
