#ifndef POOL_H
#define POOL_H

#include "common.h"

struct pool
{
    size_t nblk;
    size_t blksz;
    size_t nfree;
    size_t ninit;
    void *base;
    void *next;
};

static inline void *_idx2addr(const struct pool *p, size_t i)
{
    return (uint8_t *)p->base+(i*p->blksz);
}

static inline size_t _addr2idx(const struct pool *p, void *ptr)
{
    return (((size_t)((uint8_t *)ptr - (uint8_t *)p->base))/p->blksz);
}

static inline void pool_init(struct pool *p, void *base, size_t nblk, size_t blksz)
{
    zero_structp(p);
    p->base = p->next = base;
    p->nblk = p->nfree = nblk;
    p->blksz = blksz;
}

static inline void *palloc(struct pool *p)
{
    if (p->ninit < p->nblk) {
        size_t *ptr = (void *)_idx2addr(p, p->ninit);
        p->ninit++;
        *ptr = p->ninit;
    }
    void *ret = NULL;
    if (p->nfree) {
        ret = p->next;
        p->nfree--;
        if (p->nfree) {
            p->next = _idx2addr(p, *((size_t *)p->next));
        } else {
            p->next = NULL;
        }
    }
    return ret;
}

static inline void pfree(struct pool *p, void *ptr)
{
    if (p->next) {
        (*(size_t *)ptr) = _addr2idx(p, p->next);
        p->next = ptr;
    } else {
        *((size_t *)p) = p->nblk;
        p->next = ptr;
    }
    p->nfree++;
}

#endif
