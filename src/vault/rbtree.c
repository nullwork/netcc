#include "rbtree.h"

#define RBBLK (0)
#define RBRED (1)

#define RBNIL (&sentinel)
static struct rbnode sentinel = { RBBLK, RBNIL, RBNIL, NULL };

static void rotate_left(struct rbtree *t, struct rbnode *x);
static void rotate_right(struct rbtree *t, struct rbnode *x);
static void insert_fixup(struct rbtree *t, struct rbnode *x);
static void delete_fixup(struct rbtree *t, struct rbnode *x);

void rbtree_init(struct rbtree *t, size_t nodesz, rbcmp cmp)
{
    zero_structp(t);
    t->root = RBNIL;
    t->nodesz = nodesz;
    t->cmp = cmp;
}

void rbtree_insert(struct rbtree *t, struct rbnode *x)
{
    struct rbnode *cur = t->root;
    struct rbnode *parent = NULL;
    int cmp = 0;
    while (cur != RBNIL) {
        cmp = t->cmp(x, cur);
        parent = cur;
        cur = (cmp <= 0) ? cur->left : cur->right;
    }
    x->color = RBRED;
    x->left = x->right = RBNIL;
    x->parent = parent;
    if (parent) {
        if (cmp <= 0) {
            parent->left = x;
        } else {
            parent->right = x;
        }
    } else {
        t->root = x;
    }
    insert_fixup(t, x);
}

void rbtree_delete(struct rbtree *t, struct rbnode *z)
{
    struct rbnode *y;
    if (z->left == RBNIL || z->right == RBNIL) {
        y = z;
    } else {
        y = z->right;
        while (y->left != RBNIL)
            y = y->left;
    }
    struct rbnode *x;
    if (y->left != RBNIL) {
        x = y->left;
    } else {
        x = y->right;
    }
    x->parent = y->parent;
    if (y->parent) {
        if (y == y->parent->left) {
            y->parent->left = x;
        } else {
            y->parent->right = x;
        }
    } else {
        t->root = x;
    }
    if (y != z)
        memcpy(z+1, y+1, t->nodesz-sizeof(struct rbnode)); // NOLINT
    if (y->color == RBBLK)
        delete_fixup(t, x);
}

struct rbnode *rbtree_leftmost(struct rbnode *x)
{
    if (x == RBNIL)
        return NULL;
    struct rbnode *next = x;
    while(next != RBNIL) {
        x = next;
        next = next->left;
    }
    return x;
}

struct rbnode *rbtree_rightmost(struct rbnode *x)
{
    if (x == RBNIL)
        return NULL;
    struct rbnode *next = x;
    while(next != RBNIL) {
        x = next;
        next = next->right;
    }
    return x;
}

struct rbnode *rbtree_upper_bound(struct rbtree *t, struct rbnode *x)
{
    struct rbnode *best = NULL;
    struct rbnode *cur = t->root;
    while (cur != RBNIL) {
        if (t->cmp(cur, x) > 0) {
            best = cur;
            cur = cur->left;
        } else {
            cur = cur->right;
        }
    }
    return best;
}

static void rotate_left(struct rbtree *t, struct rbnode *x)
{
    struct rbnode *y = x->right;
    x->right = y->left;
    if (y->left != RBNIL)
        y->left->parent = x;
    if (y != RBNIL)
        y->parent = x->parent;
    if (x->parent) {
        if (x == x->parent->left) {
            x->parent->left = y;
        } else {
            x->parent->right = y;
        }
    } else {
        t->root = y;
    }
    y->left = x;
    if (x != RBNIL)
        x->parent = y;
}

static void rotate_right(struct rbtree *t, struct rbnode *x)
{
    struct rbnode *y = x->left;
    x->left = y->right;
    if (y->right != RBNIL)
        y->right->parent = x;
    if (y != RBNIL)
        y->parent = x->parent;
    if (x->parent) {
        if (x == x->parent->right) {
            x->parent->right = y;
        } else {
            x->parent->left = y;
        }
    } else {
        t->root = y;
    }
    y->right = x;
    if (x != RBNIL)
        x->parent = y;
}

static void insert_fixup(struct rbtree *t, struct rbnode *x)
{
    while (x != t->root && x->parent->color == RBRED) {
        if (x->parent == x->parent->parent->left) {
            struct rbnode *y = x->parent->parent->right;
            if (y->color == RBRED) {
                x->parent->color = RBBLK;
                y->color = RBBLK;
                x->parent->parent->color = RBRED;
                x = x->parent->parent;
            } else {
                if (x == x->parent->right) {
                    x = x->parent;
                    rotate_left(t, x);
                }
                x->parent->color = RBBLK;
                x->parent->parent->color = RBRED;
                rotate_right(t, x->parent->parent);
            }
        } else {
            struct rbnode *y = x->parent->parent->left;
            if (y->color == RBRED) {
                x->parent->color = RBBLK;
                y->color = RBBLK;
                x->parent->parent->color = RBRED;
                x = x->parent->parent;
            } else {
                if (x == x->parent->left) {
                    x = x->parent;
                    rotate_right(t, x);
                }
                x->parent->color = RBBLK;
                x->parent->parent->color = RBRED;
                rotate_left(t, x->parent->parent);
            }
        }
    }
    t->root->color = RBBLK;
}

static void delete_fixup(struct rbtree *t, struct rbnode *x)
{
    while (x != t->root && x->color == RBBLK) {
        if (x == x->parent->left) {
            struct rbnode *w = x->parent->right;
            if (w->color == RBRED) {
                w->color = RBBLK;
                x->parent->color = RBRED;
                rotate_left(t, x->parent);
                w = x->parent->right;
            }
            if (w->left->color == RBBLK && w->right->color == RBBLK) {
                w->color = RBRED;
                x = x->parent;
            } else {
                if (w->right->color == RBBLK) {
                    w->left->color = RBBLK;
                    w->color = RBRED;
                    rotate_right(t, w);
                    w = x->parent->right;
                }
                w->color = x->parent->color;
                x->parent->color = RBBLK;
                w->right->color = RBBLK;
                rotate_left(t, x->parent);
                x = t->root;
            }
        } else {
            struct rbnode *w = x->parent->left;
            if (w->color == RBRED) {
                w->color = RBBLK;
                x->parent->color = RBRED;
                rotate_right(t, x->parent);
                w = x->parent->left;
            }
            if (w->right->color == RBBLK && w->left->color == RBBLK) {
                w->color = RBRED;
                x = x->parent;
            } else {
                if (w->left->color == RBBLK) {
                    w->right->color = RBBLK;
                    w->color = RBRED;
                    rotate_left(t, w);
                    w = x->parent->left;
                }
                w->color = x->parent->color;
                x->parent->color = RBBLK;
                w->left->color = RBBLK;
                rotate_right(t, x->parent);
                x = t->root;
            }
        }
    }
    x->color = RBBLK;
}
