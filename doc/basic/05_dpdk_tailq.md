# TAILQ浅析

`TAILQ`队列是`FreeBSD`内核中的一种队列数据结构，在一些著名的开源库中(如`DPDK`,`libevent`)有广泛的应用。

DPDK的设备驱动组织的部分就用到了TAILQ结构。

## `TAILQ`队列的定义

`TAILQ`队列有`HEAD`和`ENTRY`两种基本的数据结构

```c
#define	TAILQ_HEAD(name, type)						\
struct name {								\
	struct type *tqh_first;	/* first element */			\
	struct type **tqh_last;	/* addr of last next element */		\
}

#define TAILQ_ENTRY(type)                                            \
struct {                                                             \
    struct type *tqe_next;  /* next element */                       \
    struct type **tqe_prev;/* addr of previous next element*/        \
}   
```

注意：数据结构中的`filed`都是`type`类型的指针(或者是二级指针)，这里的`type`是用户的队列元素类型，，将`ENTRY`结构内嵌到用户的`QUEUE_ITEM`结构中：

```c
struct QUEUE_ITEM{  
    int value;  
    TAILQ_ENTRY(QUEUE_ITEM) entries;  
};  

TAILQ_HEAD(headname,QUEUE_ITEM) queue_head; 
```

这和`Linux`中`list`的组织方式不一样，后者是单纯地将`struct list_head`作为链表的一个挂接点，并没有用户的信息，具体差别可以看下图：

![](resource/tailq_vs_list.png)

##  `TAILQ`队列的操作

`TAILQ`提供了多种操作队列的`API`,比如：

```c
TAILQ_HEAD(name, type) // 定义链表头,实例化一个链表
TAILQ_ENTRY(type)       // 类似于linux中的struct list_head
TAILQ_EMPTY(head)       // 判空
TAILQ_FIRST(head)       // 检索队列的第一个元素。返回指向第一个元素的指针，如果队列为空，则返回 NULL。
TAILQ_FOREACH(var, head, field)	 // 遍历链表
TAILQ_FOREACH_REVERSE(var, head, headname, field) // 逆向遍历链表
TAILQ_INIT(head)        // 初始化链表
TAILQ_INSERT_AFTER(head, listelm, elm, field)   // 在指定元素后面插入一个元素。
TAILQ_INSERT_BEFORE(listelm, elm, field)        // 在指定元素前面插入一个元素。
TAILQ_INSERT_TAIL(head, elm, field)             // 插入链表尾部
.....
```
这些接口的实现和更多的操作接口可以参考 [FreeBSD queue](https://github.com/freebsd/freebsd/blob/master/sys/sys/queue.h)

## 难点:`TAILQ`队列中为什么`tqh_prev`和`tqh_last`要使用二级指针

要搞清楚这个问题，可以考虑如果不使用二级指针会怎么样？ 就像定义成下面这样。

```c
#define	FAKE_TAILQ_HEAD(name, type)						\
struct name {								\
	struct type *tqh_first;	/* first element */			\
	struct type *tqh_last;	/* last element */		\
}

#define FAKE_TAILQ_ENTRY(type)                                            \
struct {                                                             \
    struct type *tqe_next;  /* next element */                       \
    struct type *tqe_prev;  /*   previous element*/        \
}   
```

对比一下`TAILQ_HEAD`和`FAKE_TAILQ_HEAD` (注意其中的红线和绿线的区别)


![](resource/tailq_pointer.png)

如果想要删除队列的任意一个元素，对`FAKE_TAILQ`，我们需要特殊处理该元素是第一个元素的情况(第一个元素的`tqe_prev`指针为空)，而`TAILQ`就没有这个烦恼！

## `TAILQ`队列的遍历性能

`Linux`中的`list`只将`struct list_head`作为用户元素的挂接点，因此在正向遍历链表时，需要使用`container_of`这类接口才能获取用户的数据，而`TAILQ`由于`tqe_next`指针直接指向用户元素的类型，所以理论上，正向遍历`TAILQ`比`list`更快.但逆向遍历时,由于`TAILQ`的取用`prev`元素的操作比`next`麻烦的多，因此逆向遍历是比正向慢的(DPDK组织多种不同设备的驱动的时候完全没有理由逆向遍历，因此选择TAILQ是合理的)：

注意:DPDK 19.08中仅mlx5驱动的`mlx5_flow_stop`函数使用到了TAILQ的反向遍历`TAILQ_FOREACH_REVERSE`宏，这里是个小优化点改成linux list会有性能提升。

```c
#define	TAILQ_PREV(elm, headname, field)				\
	(*(((struct headname *)((elm)->field.tqe_prev))->tqh_last))
```

下面给出linux list和freebsd TAILQ的示例代码和性能对比。

## `TAILQ`的使用案例

tailq.c

```c
#include <stdio.h>
#include <stdlib.h> 
#include <sys/time.h>

#define TAILQ_ENTRY(type)                                            \
struct {                                                             \
    struct type *tqe_next;  /* next element */                       \
    struct type **tqe_prev;/* addr of previous next element*/        \
}   

#define	TAILQ_HEAD(name, type)						\
struct name {								\
	struct type *tqh_first;	/* first element */			\
	struct type **tqh_last;	/* addr of last next element */		\
}

#define	TAILQ_FIRST(head)	((head)->tqh_first)
#define	TAILQ_NEXT(elm, field) ((elm)->field.tqe_next)
#define	TAILQ_PREV(elm, headname, field)				\
	(*(((struct headname *)((elm)->field.tqe_prev))->tqh_last))
	
#define	TAILQ_LAST(head, headname)					\
	(*(((struct headname *)((head)->tqh_last))->tqh_last))
	
	
#define	TAILQ_INIT(head) do {						\
	TAILQ_FIRST((head)) = NULL;					\
	(head)->tqh_last = &TAILQ_FIRST((head));			\
} while (0)

#define TAILQ_INSERT_TAIL(head, elm, field) do {			\
	TAILQ_NEXT((elm), field) = NULL;				\
	(elm)->field.tqe_prev = (head)->tqh_last;			\
	*(head)->tqh_last = (elm);					\
	(head)->tqh_last = &TAILQ_NEXT((elm), field);			\
} while (0)

#define	TAILQ_INSERT_BEFORE(listelm, elm, field) do {			\
	(elm)->field.tqe_prev = (listelm)->field.tqe_prev;		\
	TAILQ_NEXT((elm), field) = (listelm);				\
	*(listelm)->field.tqe_prev = (elm);				\
	(listelm)->field.tqe_prev = &TAILQ_NEXT((elm), field);		\
} while (0)

#define	TAILQ_FOREACH(var, head, field)					\
	for ((var) = TAILQ_FIRST((head));				\
	    (var);							\
	    (var) = TAILQ_NEXT((var), field))

#define	TAILQ_FOREACH_REVERSE(var, head, headname, field)		\
	for ((var) = TAILQ_LAST((head), headname);			\
	    (var);							\
	    (var) = TAILQ_PREV((var), headname, field))
		
struct QUEUE_ITEM{  
    int value;  
    TAILQ_ENTRY(QUEUE_ITEM) entries;  
};  
TAILQ_HEAD(headname,QUEUE_ITEM) queue_head;  

#define ITEM_NUM 5000000
#define TRAVERSAL 20

int main(int argc,char **argv)
{
    struct QUEUE_ITEM *item;
    long long totaltime = 0;
    struct timeval start,end;
    long long metric[TRAVERSAL];
    int i = 0;
    
    TAILQ_INIT(&queue_head);
    for(i=1;i<ITEM_NUM;i+=1) {
        item=malloc(sizeof(struct QUEUE_ITEM));  
        item->value=i;  
        TAILQ_INSERT_TAIL(&queue_head, item, entries);  
    }  
    
    for (i = 0; i < TRAVERSAL; i++) {
        gettimeofday(&start,NULL);
        TAILQ_FOREACH(item, &queue_head, entries)
        {
            item->value++;
        }   
        gettimeofday(&end,NULL);
        metric[i] = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec); // get the run time by microsecond
    }
   
    totaltime = 0;
    for (i=0;i<TRAVERSAL;i++)
    {
        totaltime += metric[i];
    }

    printf("TAILQ traversal time is %lld us\n", totaltime/TRAVERSAL);

    for (i = 0; i < TRAVERSAL; i++)
    {
        gettimeofday(&start,NULL);
        TAILQ_FOREACH_REVERSE(item, &queue_head, headname,entries)
        {
            item->value++;
        }   
        gettimeofday(&end,NULL);
        metric[i] = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec); // get the run time by microsecond
    }
	
    totaltime = 0;
    for (i=0;i<TRAVERSAL;i++)
    {
        totaltime += metric[i];
    }

    printf("TAILQ reverse traversal time is %lld us\n", totaltime/TRAVERSAL);
    return 0; 
}
```

下面是list的示例:

list.c

```c
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>	/* for offsetof */
#include <sys/time.h>

#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})


#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)


#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

#define list_last_entry(ptr, type, member) \
	list_entry((ptr)->prev, type, member)

#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, typeof(*(pos)), member)

#define list_prev_entry(pos, member) \
	list_entry((pos)->member.prev, typeof(*(pos)), member)
	
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_first_entry(head, typeof(*pos), member);	\
	     &pos->member != (head);					\
	     pos = list_next_entry(pos, member))

#define list_for_each_entry_reverse(pos, head, member)			\
	for (pos = list_last_entry(head, typeof(*pos), member);		\
	     &pos->member != (head); 					\
	     pos = list_prev_entry(pos, member))
		 
#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

struct list_head {
	struct list_head *next, *prev;
};
static inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline void __list_add(struct list_head *new,
			      struct list_head *prev,
			      struct list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static inline void list_add(struct list_head *new, struct list_head *head)
{
	__list_add(new, head, head->next);
}

struct QUEUE_ITEM{
    int value;
    struct list_head node;
};

LIST_HEAD(queue_head);

#define ITEM_NUM 5000000
#define TRAVERSAL 20

int main()
{
    int i = 0;
    struct QUEUE_ITEM *item;
    long long totaltime = 0;
    struct timeval start,end;
    long long metric[TRAVERSAL];

    for(i=1;i<ITEM_NUM;i+=1){
        item=malloc(sizeof(struct QUEUE_ITEM));
        item->value = i;
        INIT_LIST_HEAD(&item->node);
        list_add(&item->node, &queue_head);
    }

    for (i = 0; i < TRAVERSAL; i++)
    {
        gettimeofday(&start,NULL);
        list_for_each_entry_reverse(item, &queue_head, node)
        {
            item->value++;
        }   

        gettimeofday(&end,NULL);
        metric[i] = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec); // get the run time by microsecond
    }
   
    totaltime = 0;
    for (i=0;i<TRAVERSAL;i++)
    {
        totaltime += metric[i];
    }

    printf("list reverse traversal time is %lld us\n", totaltime/TRAVERSAL);

    for (i = 0; i < TRAVERSAL; i++)
    {
        gettimeofday(&start,NULL);
        list_for_each_entry(item, &queue_head, node)
        {
            item->value++;
        }   

        gettimeofday(&end,NULL);
        metric[i] = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec); // get the run time by microsecond
    }
   
    totaltime = 0;
    for (i=0;i<TRAVERSAL;i++)
    {
        totaltime += metric[i];
    }

    printf("list traversal time is %lld us\n", totaltime/TRAVERSAL);

    return 0;
}
```

运行性能如下对比:

```shell
TAILQ traversal time is 16437 us
TAILQ reverse traversal time is 26830 us

list reverse traversal time is 18110 us
list traversal time is 20560 us
```