#include "rbtree.h"
#include "timer.h"
#include "log.h"

int timer_init(timer_root_t *root)
{
    if(root == NULL) return 0;

    root->rbroot = RB_ROOT;
    root->sum = 0;
    return 1;
}

int timer_insert(timer_root_t *root, timer_node_t *node)
{
    if(root == NULL || node == NULL || node->trigger == true) return 0;

    struct rb_node **rbnode = &root->rbroot.rb_node, *parent = NULL;
    while(*rbnode)
    {
        timer_node_t *pos = rb_entry(*rbnode, timer_node_t, rbnode);
        long long result = node->expire - pos->expire;

        parent = *rbnode;
        if (result < 0)
            rbnode = &((*rbnode)->rb_left);
        else if (result > 0)
            rbnode = &((*rbnode)->rb_right);
        else
            return 0;
    }

    rb_link_node(&node->rbnode, parent, rbnode);
    rb_insert_color(&node->rbnode, &root->rbroot);
    node->trigger = true;
    root->sum ++;
    return 1;
}

timer_node_t* timer_search(timer_root_t *root, long long expire)
{
    if(root == NULL) return NULL;

    struct rb_node *rbnode = root->rbroot.rb_node;
    while(rbnode)
    {
        timer_node_t *pos = rb_entry(rbnode, timer_node_t, rbnode);
        long long result = expire - pos->expire;

        if (result < 0)
            rbnode = rbnode->rb_left;
        else if (result > 0)
            rbnode = rbnode->rb_right;
        else
            return pos;
    }
    return NULL;
}

void timer_erase(timer_root_t *root, long long expire)
{
    if(root == NULL) return;

    timer_node_t *pos = timer_search(root, expire);
    if(pos)
    {
        rb_erase(&pos->rbnode, &root->rbroot);
        RB_CLEAR_NODE(&pos->rbnode);
        pos->trigger = false;
        root->sum --;
    }
}

int timer_remove(timer_root_t *root, timer_node_t *node)
{
    if(root == NULL || node == NULL || node->trigger == false) return 0;

    rb_erase(&node->rbnode, &root->rbroot);
    RB_CLEAR_NODE(&node->rbnode);
    node->trigger = false;
    root->sum --;
    return 1;
}

int timer_set_expire(timer_node_t *node, long long expire)
{
    if(node == NULL) return 0;
    node->expire = expire;
    return 1;
}

long long timer_get_expire(timer_node_t *node)
{
    if(node == NULL) return 0;
    return node->expire;
}

int timer_sum(timer_root_t *root)
{
    if(root == NULL) return 0;
    return root->sum;
}

void timer_beat(timer_root_t *root, long long now)
{
    if(root == NULL) return;

    timer_node_t *pos = NULL;
    struct rb_node *rbnode = NULL;
    for(rbnode = rb_first(&root->rbroot); rbnode != NULL; rbnode = rb_next(rbnode))
    {
        pos = rb_entry(rbnode, timer_node_t, rbnode);
        if(now < pos->expire)               //升序排列
        {
            log_debug("sum - %d\n", root->sum);
            log_debug("now - %lld\n", now);
            log_debug("expire - %lld\n", pos->expire);
            break;
        }
        pos->handler(pos->data);            //执行回调
    }
}

void timer_dump(timer_root_t *root)
{
    if(root == NULL) return;

    timer_node_t *pos = NULL;
    struct rb_node *rbnode = NULL;
    for(rbnode = rb_first(&root->rbroot); rbnode != NULL; rbnode = rb_next(rbnode))
    {
        pos = rb_entry(rbnode, timer_node_t, rbnode);
        log_debug("expire - %lld\n", pos->expire);
    }
}

void timer_exit(timer_root_t *root)
{
    if(root == NULL) return;

    timer_node_t *pos = NULL;
    struct rb_node *rbnode = NULL;
    while((rbnode = rb_first(&root->rbroot)))
    {
        pos = rb_entry(rbnode, timer_node_t, rbnode);
        log_debug("expire - %lld\n", pos->expire);
        timer_remove(root, pos);
    }
}
