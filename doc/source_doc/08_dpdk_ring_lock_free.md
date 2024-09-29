# dpdk队列多生产者多消费者无锁原理

在较新版本的dpdk 19.08中，dpdk无锁队列中无锁操作的实现分为c11版本的rte_ring_c11_mem.h以及通用性更强的rte_ring_generic.h中。

最新版本的DPDK(截止2024年9月26日)无锁队列中无锁操作的实现分为C11版本的rte_ring_c11_pvt.h和通用性更强的rte_ring_generic_pvt.h。

C11版本采用的是编译器提供的指令`__atomic_store_n`等宏(最新版本是汇编指令)，而通用版本是采用的系统的内存屏障。

本文主要分析通用版本的入队和出队操作。

# ring结构体

dpdkring结构体：

```c
struct rte_ring_headtail {
    volatile uint32_t head;   // 生产者/消费者 出入队列的index
    volatile uint32_t tail;   //  所有操作完成后，生产者/消费者 出入队列的index
    uint32_t single;          // 是否是单线程
};


struct rte_ring {
    char name[RTE_MEMZONE_NAMESIZE] __rte_cache_aligned; /**< Name of the ring. */
    int flags;               /**< Flags supplied at creation. */
    const struct rte_memzone *memzone; // ret_ring结构体及ring的对象的大页内存空间
    uint32_t size;                  // 对象的个数，必须是2的n次方
    uint32_t mask;                  // 对象个数减1
    uint32_t capacity;       /**< 可用 size of ring */
    struct rte_ring_headtail prod;  生产者在环形队列中的index，队尾
    struct rte_ring_headtail cons;  消费者在环形队列中的index，队头
    void * ring[0]   //队列中所有对象开始的地址
};
```

# 入队操作

入队的实际函数为如下:

```c
static __rte_always_inline unsigned int
__rte_ring_do_enqueue(struct rte_ring *r, void * const *obj_table,
		 unsigned int n, enum rte_ring_queue_behavior behavior,
		 unsigned int is_sp, unsigned int *free_space)
{
	uint32_t prod_head, prod_next;
	uint32_t free_entries;

	n = __rte_ring_move_prod_head(r, is_sp, n, behavior,
			&prod_head, &prod_next, &free_entries);
	if (n == 0)
		goto end;

	ENQUEUE_PTRS(r, &r[1], prod_head, obj_table, n, void *);

	update_tail(&r->prod, prod_head, prod_next, is_sp, 1);
end:
	if (free_space != NULL)
		*free_space = free_entries - n;
	return n;
}
```

核心就三个函数`__rte_ring_move_prod_head`，`ENQUEUE_PTRS`(是宏，理解为函数)，`update_tail`。

1. 更新环形队列里面生产者的index，即r->prod.head更新

__rte_ring_move_prod_head简化版如下:

```c
static __rte_always_inline unsigned int
__rte_ring_move_prod_head(struct rte_ring *r, unsigned int is_sp,
		unsigned int n, enum rte_ring_queue_behavior behavior,
		uint32_t *old_head, uint32_t *new_head,
		uint32_t *free_entries)
{
    do {
        *old_head = r->prod.head;
        *new_head = *old_head + n;
        //比较值r->prod.head同oldhead相同则设置新值，原子操作,
        success = rte_atomic32_cmpset(&r->prod.head,
					*old_head, *new_head);
    }while (unlikely(success == 0));  //循环确保另外入队线程先更新r->prod.head成功，本次入队重新计算head值
}
```

2. 对象指针赋值：

操作在`ENQUEUE_PTRS`宏中，具体代码为

```c
ring[idx++] = obj_table[i++];
```

3. 赋值成功后更新`r->prod.tail`值，赋值成跟`r->prod.head`一样，表示所有操作完成。

代码是`update_tail(&r->prod, prod_head, prod_next, is_sp, 1);`。

注意：出队操作的话，在出队前先计算可用对象个数使用`cons.head - prod.tail + mask`的值计算.这样没做完的入队对象不会计算到其中
内存写屏障确保`r->prod.tail`值得更新在对象赋值成功之后，出队列不会出错

```c
static __rte_always_inline void
update_tail(struct rte_ring_headtail *ht, uint32_t old_val, uint32_t new_val,
		uint32_t single, uint32_t enqueue)
{
	if (enqueue)
		rte_smp_wmb();
	else
		rte_smp_rmb();
	/*
	 * If there are other enqueues/dequeues in progress that preceded us,
	 * we need to wait for them to complete
	 */
	if (!single)
		while (unlikely(ht->tail != old_val)) // 另外线程入队先更新成功head值，等另外线程tail值更新后，才能更新本次
			rte_pause();

	ht->tail = new_val;
}
// 其中while逻辑相当于

while (unlikely(r->prod.tail != old_head))   //另外线程入队先更新成功head值，等另外线程tail值更新后，才能更新本次
                 rte_pause();  // 自旋等待
     r->prod.tail = new_head
```


# 出队操作

出队操作函数如下:

```c
static __rte_always_inline unsigned int
__rte_ring_do_dequeue(struct rte_ring *r, void **obj_table,
		 unsigned int n, enum rte_ring_queue_behavior behavior,
		 unsigned int is_sc, unsigned int *available)
{
	uint32_t cons_head, cons_next;
	uint32_t entries;

	n = __rte_ring_move_cons_head(r, (int)is_sc, n, behavior,
			&cons_head, &cons_next, &entries);
	if (n == 0)
		goto end;

	DEQUEUE_PTRS(r, &r[1], cons_head, obj_table, n, void *);

	update_tail(&r->cons, cons_head, cons_next, is_sc, 0);

end:
	if (available != NULL)
		*available = entries - n;
	return n;
}
```

1. 先更新环形队列里面消费者的index ：r->cons.head

实现是函数`__rte_ring_move_cons_head`。

```c
static __rte_always_inline unsigned int
__rte_ring_move_cons_head(struct rte_ring *r, unsigned int is_sc,
		unsigned int n, enum rte_ring_queue_behavior behavior,
		uint32_t *old_head, uint32_t *new_head,
		uint32_t *entries)
{
   do{
        *old_head = r->cons.head;
        *new_head = *old_head + n;
        //比较(r->cons.head，oldhead 值相同则设置新值，原子操作
        success = rte_atomic32_cmpset(&r->cons.head, *old_head,
                            *new_head);
    }while (unlikely(success == 0)); //循环确保另外出队线程先更新r->cons.head成功，本次出队重新计算head值
}
```

2. 对象指针赋值：

`DEQUEUE_PTRS`宏实现相应逻辑。

```c
obj_table[i++] = ring[i++];
```

3. 赋值成功后更新r->cons.tail值，赋值成跟r->cons.head一样，表示所有操作完成。

具体函数实现为`update_tail(&r->cons, cons_head, cons_next, is_sc, 0);`


入队计算空闲个数使用`prod.head - cons.tail + mask`的值计算.这样没有做完的出队对象不会计算到其中内存读屏障配对入队了的内存写屏障，确保出队列计算的对象个数值的正确。

update_tail在出队中的代码相当于如下:

```c
      while (unlikely(r->cons.tail != old_head))  //另外线程出队先更新成功head值，等另外线程tail值更新后，才能更新本次
                  rte_pause(); // 自旋等待
      r->cons.tail = new_head
```

# 总结

DPDK中达成无锁队列主要通过两个方面:

1. 读写屏障
2. 通过计算(出队计算可以对象个数，入队计算空闲个数)得出head值，先更新head值。等其他线程的tail更新完成后更新本次入/出队操作。