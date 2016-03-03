/*
 *  BIRD -- Utility functions for libwin module.
 *
 *  Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_WIN_UTIL_H_
#define _BIRD_WIN_UTIL_H_

#include <windef.h>

LPVOID wmalloc(ULONG size);
LPVOID wrealloc(void *ptr, ULONG size);

#endif
