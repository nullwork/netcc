#ifndef PROGRAM_H
#define PROGRAM_H

#include <stddef.h>
#include <stdint.h>

#define COMPILE_TIMEOUT 5

#define PGMMAXOUT (1 << 13)

// Compile-step result codes
// TODO: enum?
#define CMPINTERR (-1)
#define CMPOK (0)
#define CMPERR (1)
#define CMPTIMEOUT (2)

// Run-step result codes
// TODO: enum?
#define PGMINTERR (-1)
#define PGMOK (0)
#define PGMRTERR (1)
#define PGMTIMEOUT (2)

int compile_program(char *cmpin, char *cmpout, char *output, uint32_t *outsz, uint32_t timeout);
int run_program(char *path, char *output, uint32_t *outsz, uint32_t timeout);

#endif
