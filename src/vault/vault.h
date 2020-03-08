#ifndef VAULT_H
#define VAULT_H

#include "common.h"

#define DBERR -1
#define DBOK 0

struct db;

struct db *db_open(const char *path);
void db_close(struct db *db);

int db_insert(struct db *db, const char *key, uint32_t ksz, const void *val, uint32_t vsz);
int db_remove(struct db *db, const char *key, uint32_t ksz);
void *db_get(struct db *db, const char *key, uint32_t ksz, uint32_t *vsz);

#endif
