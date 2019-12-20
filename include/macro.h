#ifndef _MACRO_H
#define _MACRO_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#include <wchar.h>


#define typeof(a) __typeof__(a)
#define sqr(x) ((double)(x)*(x))
#define SWAP(a, b) do {typeof (a) __tmp = a; a = b; b = __tmp;} while (0)

#define SYSCALL(estat, func, ...)					\
({									\
	int __ret;							\
									\
									\
	while ((__ret = ((func)(__VA_ARGS__))) == -1 && errno == EINTR)	\
		;							\
									\
	if (__ret == -1) {						\
		perror(#func "(" #__VA_ARGS__ ")");			\
		if (estat != 0)						\
			exit(estat);					\
	}								\
									\
	__ret;								\
})

#ifndef FULL_LOG
#define _int_logit _int_logit_short
#else
#define _int_logit _int_logit_full
#endif

#define _int_logit_short(fp, prefix, fmt, ...)				\
do {									\
	fprintf(fp, prefix "%20.20s| " fmt, __FUNCTION__, ##__VA_ARGS__);\
	fflush(fp);							\
} while (0)

#define _int_logit_full(fp, prefix, fmt, ...)				\
do {									\
	fprintf(fp, prefix "%7.7s:%d %20.20s| " fmt,			\
	    __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__);		\
	fflush(fp);							\
} while (0)

#define debug(fmt, ...)   _int_logit(stderr, "[D] ", fmt, ##__VA_ARGS__)
#define warning(fmt, ...) _int_logit(stderr, "[W] ", fmt, ##__VA_ARGS__)
#define error(fmt, ...)   _int_logit(stderr, "[E] ", fmt, ##__VA_ARGS__)
#define perror(str)							\
do {									\
	char buf[32];							\
									\
	strerror_r(errno, buf, 32);					\
	_int_logit(stderr, "[E] ", "%s: %s\n", str, buf);		\
} while(0)

static inline void*
xmalloc(size_t size)
{
	void *ret;

	errno = 0;
	ret = malloc(size);

	if (size != 0 && ret == NULL) {
		perror("malloc()");
		exit(EXIT_FAILURE);
	}

	return ret;
}

static inline void*
xrealloc(void *ptr, size_t size)
{
	void *ret;

	ret = realloc(ptr, size);

	if (size != 0 && ret == NULL) {
		perror("realloc()");
		exit(EXIT_FAILURE);
	}

	return ret;
}

#define xassert(var)							\
({									\
	typeof (var) __var = var;					\
									\
									\
	if (!__var) {							\
		fprintf(stderr, "%s:%d: %s: Assertion `%s' failed.\n",	\
			__FILE__, __LINE__, __func__, #var);		\
		fflush(stderr);						\
		exit(1);						\
	}								\
									\
	__var;								\
})

#define list_init(p)							\
({									\
	typeof (p) __p;							\
									\
									\
	__p = xmalloc(sizeof (typeof (*__p)));				\
	memset(&__p->_list, 0, sizeof (struct list_node));		\
									\
	__p->_list.meta = xmalloc(sizeof (struct list_meta));		\
	__p->_list.meta->offset = offsetof(typeof (*__p), _list);	\
	__p->_list.meta->head = &__p->_list;				\
	__p->_list.meta->tail = &__p->_list;				\
	__p->_list.prev = NULL;						\
	__p->_list.next = NULL;						\
									\
	p = __p;							\
})

#define list_alloc_at_end(p)						\
({									\
	typeof (p) __newp, __p = p;					\
									\
	if (__p) {							\
		__newp = xmalloc(sizeof (typeof (*__p)));		\
		__newp->_list.meta = __p->_list.meta;			\
		__newp->_list.prev = __p->_list.meta->tail;		\
		__newp->_list.next = NULL;				\
		__newp->_list.meta->tail = &(__newp->_list);		\
		if (__newp->_list.prev != NULL)				\
			__newp->_list.prev->next = &(__newp->_list);	\
	}								\
	else								\
 		list_init(__newp);					\
									\
	__newp;								\
})

#define list_delete(p)							\
({									\
	typeof (p) __head = NULL, __p = xassert(p);			\
									\
									\
	if (__p->_list.prev == NULL)					\
		__p->_list.meta->head = __p->_list.next;		\
	else								\
		__p->_list.prev->next = __p->_list.next;		\
									\
	if (__p->_list.next == NULL)					\
		__p->_list.meta->tail = __p->_list.prev;		\
	else								\
		__p->_list.next->prev = __p->_list.prev;		\
									\
	if (__p->_list.meta->head != NULL)				\
		__head = (typeof (__p)) ((int8_t*)__p->_list.meta->head - __p->_list.meta->offset);	\
									\
	if (__p->_list.prev == NULL && __p->_list.next == NULL)		\
		free(__p->_list.meta);					\
									\
	free(__p);							\
									\
	__head;								\
})

#define list_get_prev(p)						\
({									\
	typeof (p) __ret = NULL, __p = xassert(p);			\
									\
									\
	if (__p->_list.prev != NULL)					\
		__ret = (void*)((int8_t*)__p->_list.prev - __p->_list.meta->offset); \
									\
	__ret;								\
})

#define list_get_next(p)						\
({									\
	typeof (p) __ret = NULL, __p = xassert(p);			\
									\
									\
	if (__p->_list.next != NULL)					\
		__ret = (void*)((int8_t*)__p->_list.next - __p->_list.meta->offset); \
									\
	__ret;								\
})

#define list_get_head(p)						\
({									\
	typeof (p) __ret = NULL, __p = xassert(p);			\
									\
									\
	if (__p->_list.meta->head != NULL)				\
		__ret = (void*)((int8_t*)__p->_list.meta->head - __p->_list.meta->offset);	\
									\
	__ret;								\
})

#define list_get_tail(p)						\
({									\
	typeof (p) __ret = NULL, __p = xassert(p);			\
									\
									\
	if (__p->_list.meta->tail != NULL)				\
		__ret = (void*)((int8_t*)__p->_list.meta->tail - __p->_list.meta->offset);	\
									\
	__ret;								\
})

#define list_find(p, var, val)						\
({									\
	typeof (p) __entry;						\
									\
									\
	list_foreach (p, __entry)					\
		if (__entry->var == (val))				\
			break;						\
									\
	__entry;							\
})

#define list_foreach(head, entry) for (entry = head; entry != NULL; entry = list_get_next(entry))

struct list_meta {
	struct list_node *head, *tail;
	int offset;
};

struct list_node {
	struct list_meta *meta;
	struct list_node *prev, *next;
};

#endif // _MACRO_H
