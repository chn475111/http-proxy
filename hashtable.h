#ifndef __HASHTABLE__
#define __HASHTABLE__

#include "uthash.h"
#include "connection.h"

void hash_create(connection_t **head);

void hash_add(connection_t **head, connection_t *conn);

void hash_del(connection_t **head, connection_t *conn);

connection_t* hash_find(connection_t **head, int fd);

unsigned int hash_count(connection_t **head);

void hash_sort(connection_t **head);

void hash_dump(connection_t **head);

void hash_destroy(connection_t **head);

#endif
