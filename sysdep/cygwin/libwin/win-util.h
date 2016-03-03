
#ifndef _BIRD_WIN_UTIL_H_
#define _BIRD_WIN_UTIL_H_

#include <windef.h>

LPVOID wmalloc(ULONG size);
LPVOID wrealloc(void *ptr, ULONG size);

#endif
