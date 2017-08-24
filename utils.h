#ifndef __UTILS_H__
#define __UTILS_H__

#define min(x,y) ({ \
        typeof(x) _x = (x);     \
        typeof(y) _y = (y);     \
        (void) (&_x == &_y);    \
        _x < _y ? _x : _y; })

#define max(x,y) ({ \
        typeof(x) _x = (x);     \
        typeof(y) _y = (y);     \
        (void) (&_x == &_y);    \
        _x > _y ? _x : _y; })

int get_proc_num();

int set_proc_priority(int prio);

int set_proc_affinity(int id);

int set_conn_limit(unsigned max);

#endif
