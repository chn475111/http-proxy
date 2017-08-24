/**
 * @author lijk@infosec.com.cn
 * @version 0.0.1
 * @date 2016-10-11 16:12:45
 */
#ifndef __TIMER_H__
#define __TIMER_H__

#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <sys/time.h>

typedef void (*timer_cb)(void*);

//根结点
typedef struct timer_root_s
{
    struct rb_root rbroot;
    int sum;                //计时器总数
}timer_root_t;

//叶结点
typedef struct timer_node_s
{
    struct rb_node rbnode;
    long long expire;       //计时器到期时间点(红黑树键值)
    bool trigger;           //计时器插入状态 true: 已插入; false: 未插入

    timer_cb handler;       //工作回调函数
    void *data;             //工作回调函数参数
}timer_node_t;

int timer_init(timer_root_t *root);

int timer_insert(timer_root_t *root, timer_node_t *node);

timer_node_t* timer_search(timer_root_t *root, long long expire);

void timer_erase(timer_root_t *root, long long expire);

int timer_remove(timer_root_t *root, timer_node_t *node);

int timer_set_expire(timer_node_t *node, long long expire);

long long timer_get_expire(timer_node_t *node);

int timer_sum(timer_root_t *root);

void timer_beat(timer_root_t *root, long long now);

void timer_dump(timer_root_t *root);

void timer_exit(timer_root_t *root);

#endif
