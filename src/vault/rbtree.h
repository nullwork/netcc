#ifndef RBTREE_H
#define RBTREE_H

#include "common.h"

struct rbnode
{
    char color;
    struct rbnode *left;
    struct rbnode *right;
    struct rbnode *parent;
};

typedef int (*rbcmp)(const struct rbnode *, const struct rbnode *);

struct rbtree
{
    struct rbnode *root;
    size_t nodesz;
    rbcmp cmp;
};

void rbtree_init(struct rbtree *t, size_t nodesz, rbcmp cmp);
void rbtree_insert(struct rbtree *t, struct rbnode *x);
void rbtree_delete(struct rbtree *t, struct rbnode *z);
struct rbnode *rbtree_leftmost(struct rbnode *x);
struct rbnode *rbtree_rightmost(struct rbnode *x);
struct rbnode *rbtree_upper_bound(struct rbtree *t, struct rbnode *x);

#endif
