#include "pool.h"
#include "rbtree.h"
#include "vault.h"
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "murmurhash.inl"

// =============================================================================
//      Defaults
// =============================================================================

// Default number of buckets
#define NBDEFAULT (1 << 20)
// Default number of free blocks
#define NFBDEFAULT (1 << 12)
// Default alignment
#define ALIGNDEFAULT (1 << 6)

// =============================================================================
//      Metadata
// =============================================================================

// Bucket type.
#define BTYPE uint64_t
// Bucket size on disk
#define BSZ sizeof(BTYPE)

// Record metadata on disk:
// [ 4 B ][ 4 B ][ 4 B ][ 8 B ]
//   ksz    vsz     sz    nxt

// Record metadata size (on disk)
#define MRECSZ (offsetof(struct dbrec, offset))
// Offset of the "key size" field
#define MKSZOFF (offsetof(struct dbrec, ksz))
// Offset of the "value size" field
#define MVSZOFF (offsetof(struct dbrec, vsz))
// Offset of the "size" field
#define MSZOFF (offsetof(struct dbrec, sz))
// Offset of the "next" field
#define MNEXTOFF (offsetof(struct dbrec, next))

// =============================================================================
//      Limits
// =============================================================================

// Maximum key size
#define MAXKEYSZ (512)
// Maximum value size
#define MAXVALSZ (UINT32_MAX - MRECSZ - MAXKEYSZ)

#pragma pack(push, 1)
struct dbmeta
{
    uint64_t nb;
    uint64_t nfb;
};

struct dbrec
{
    uint32_t ksz;
    uint32_t vsz;
    uint32_t sz;
    uint64_t next;

    uint64_t offset;
    const char *kbuf;
    const char *vbuf;
}; 
#pragma pack(pop)

struct dbfb
{
    struct rbnode node;
    uint64_t off;
    uint32_t sz;
};

struct db
{
    int fd;
    int pad;

    struct rbtree fbt;
    struct pool fbp;

    uint64_t nfb;
    uint64_t nb;
    uint64_t *bmap;

    size_t mapsz;
    void *map;
};

static inline int write_record(int fd, const struct dbrec *r);
static inline struct dbfb *get_free_block(struct db *db, uint32_t sz);
static inline int fbcmp(const struct rbnode *a, const struct rbnode *b);

struct db *db_open(const char *path)
{
    int fd = open(path, O_RDWR|O_CREAT, S_IWUSR|S_IRUSR);
    if (fd < 0)
        return NULL;

    struct stat fs;
    if (fstat(fd, &fs) < 0) {
        close(fd);
        return NULL;
    }

    struct dbmeta *meta;
    size_t mapsz = sizeof *meta + BSZ*NBDEFAULT;
    void *map = mmap(NULL, mapsz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        close(fd);
        return NULL;
    }

    if (fs.st_size == 0) {
        if (ftruncate(fd, (off_t)mapsz) < 0) {
            close(fd);
            return NULL;
        }
        meta = map;
        meta->nb = NBDEFAULT;
        memset((uint8_t *)map + sizeof *meta, 0xff, BSZ*NBDEFAULT); // NOLINT
    } else {
        meta = map;
    }

    size_t sz = sizeof(struct db)+NFBDEFAULT*sizeof(struct dbfb);
    struct db *db = calloc(1, sz);
    if (!db) {
        munmap(map, mapsz);
        close(fd);
        return NULL;
    }
    pool_init(&db->fbp, (void *)((uint8_t *)db+sizeof *db), NFBDEFAULT, sizeof(struct dbfb));
    rbtree_init(&db->fbt, sizeof(struct dbfb), fbcmp);
    db->fd = fd;
    db->nfb = meta->nfb;
    db->nb = meta->nb;
    db->bmap = (uint64_t *)(void *)((uint8_t *)map + sizeof meta);
    db->mapsz = mapsz;
    db->map = map;
    return db;
}

void db_close(struct db *db)
{
    munmap(db->map, db->mapsz);
    close(db->fd);
    free(db);
}

int db_insert(struct db *db, const char *key, uint32_t ksz, const void *val, uint32_t vsz)
{
    uint64_t hash = murmurhash64a(key, ksz, 0);
    uint64_t bidx = hash % db->nb;
    uint64_t boff = db->bmap[bidx];

    uint64_t roff;
    uint32_t recsz = MRECSZ+ksz+vsz;
    struct dbfb *fb = get_free_block(db, recsz);
    if (fb) {
        roff = fb->off;
        recsz = fb->sz;
        rbtree_delete(&db->fbt, (struct rbnode *)fb);
        pfree(&db->fbp, fb);
    } else {
        struct stat fs;
        if (fstat(db->fd, &fs) < 0)
            return DBERR;
        roff = (size_t)fs.st_size;
        recsz = align_to(MRECSZ+ksz+vsz, ALIGNDEFAULT);
    }

    if (boff == UINT64_MAX) {
        db->bmap[bidx] = roff;
    } else {
        while (1) {
            struct dbrec rec;
            ssize_t n = pread(db->fd, &rec, MRECSZ, (off_t)boff);
            if (n < 0 || (size_t)n != MRECSZ)
                return DBERR;

            if (rec.next) {
                boff = rec.next;
            } else {
                break;
            }
        }
        ssize_t n = pwrite(db->fd, &roff, sizeof roff, (off_t)(boff + MNEXTOFF));
        if (n < 0 || (size_t)n != sizeof roff)
            return DBERR;
    }
    struct dbrec rec;
    rec.offset = roff;
    rec.next = 0;
    rec.ksz = ksz;
    rec.vsz = vsz;
    rec.sz = recsz;
    rec.kbuf = key;
    rec.vbuf = val;
    return write_record(db->fd, &rec);
}

int db_remove(struct db *db, const char *key, uint32_t ksz)
{
    uint64_t hash = murmurhash64a(key, ksz, 0);
    uint64_t bidx = hash % db->nb;
    uint64_t boff = db->bmap[bidx];
    if (boff == UINT64_MAX) {
        return DBERR;
    } else {
        uint64_t last = bidx;
        while (1) {
            struct dbrec rec;
            ssize_t n = pread(db->fd, &rec, MRECSZ, (off_t)boff);
            if (n < 0 || (size_t)n != MRECSZ)
                return DBERR;

            // First pass, test key length
            if (rec.ksz == ksz) {
                char kbuf[MAXKEYSZ];
                n = pread(db->fd, kbuf, ksz, (off_t)(boff+MRECSZ));
                if (n < 0 || (uint32_t)n != ksz)
                    return DBERR;

                // Second pass, test string equality
                if (strncmp(kbuf, key, ksz) == 0) {
                    if (last >= db->mapsz) {
                        uint64_t next = 0;
                        n = pwrite(db->fd, &next, sizeof next, (off_t)(last+MNEXTOFF));
                        if (n < 0 || (size_t)n != sizeof next)
                            return DBERR;
                    } else {
                        db->bmap[last] = UINT64_MAX;
                    }

                    struct dbfb *fb = palloc(&db->fbp);
                    zero_structp(fb);
                    fb->off = boff;
                    fb->sz = rec.sz;
                    rbtree_insert(&db->fbt, (struct rbnode *)fb);
                    return DBOK;
                }
            }

            if (rec.next) {
                last = boff;
                boff = rec.next;
            } else {
                break;
            }
        }
    }
    return DBERR;
}

void *db_get(struct db *db, const char *key, uint32_t ksz, uint32_t *vsz)
{
    *vsz = 0;
    uint64_t hash = murmurhash64a(key, ksz, 0);
    uint64_t bidx = hash % db->nb;
    uint64_t boff = db->bmap[bidx];
    if (boff == UINT64_MAX)
        return NULL;

    while (1) {
        struct dbrec rec;
        ssize_t n = pread(db->fd, &rec, MRECSZ, (off_t)boff);
        if (n < 0 || (size_t)n != MRECSZ)
            return NULL;

        if (rec.ksz == ksz) {
            char kbuf[MAXKEYSZ];
            n = pread(db->fd, kbuf, ksz, (off_t)(boff+MRECSZ));
            if (n < 0 || (uint32_t)n != ksz)
                return NULL;

            if (strncmp(kbuf, key, ksz) == 0) {
                void *vbuf = malloc(rec.vsz);
                if (!vbuf)
                    return NULL;

                n = pread(db->fd, vbuf, rec.vsz, (off_t)(boff+MRECSZ+ksz));
                if (n < 0 || (uint32_t)n != rec.vsz) {
                    free(vbuf);
                    return NULL;
                }
                return vbuf;
            }
        }

        if (rec.next) {
            boff = rec.next;
        } else {
            break;
        }
    }
    return NULL;
}

static inline int write_record(int fd, const struct dbrec *r)
{
    size_t sz = MRECSZ + r->sz;
    uint8_t *buf = malloc(sz);
    if (!buf)
        return DBERR;
    uint8_t *p = buf;
    memcpy(p, r, MRECSZ);       p += MRECSZ; // NOLINT
    memcpy(p, r->kbuf, r->ksz); p += r->ksz; // NOLINT
    memcpy(p, r->vbuf, r->vsz); // NOLINT
    ssize_t n = pwrite(fd, buf, sz, (off_t)r->offset);
    free(buf);
    if (n < 0 || (size_t)n != sz) {
        return DBERR;
    } else {
        return DBOK;
    }
}

static inline struct dbfb *get_free_block(struct db *db, uint32_t sz)
{
    struct dbfb fb = {0};
    fb.sz = sz;
    return (struct dbfb *)rbtree_upper_bound(&db->fbt, (struct rbnode *)&fb);
}

static inline int fbcmp(const struct rbnode *a, const struct rbnode *b)
{
    const struct dbfb *fba = (const struct dbfb *)a;
    const struct dbfb *fbb = (const struct dbfb *)b;
    if (fba->sz < fbb->sz) {
        return -1;
    } else if (fba->sz == fbb->sz) {
        return 0;
    } else {
        return 1;
    }
}
