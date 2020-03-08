#ifndef COMMON_H
#define COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define UNUSED(x) (void)(x)

#define zero_struct(x) memset(&(x),0x00,sizeof((x))) // NOLINT
#define zero_structp(x) if((x))do{memset((x),0x00,sizeof(*(x)));}while(0) // NOLINT
#define align_to(n, m) (((n)+(m)-1)/(m))*(m)

#endif
