/*
 *  BIRD -- Utility functions for libwin module.
 *
 *  Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <malloc.h>
#include <stdlib.h>
#include <windef.h>

#include "win-util.h"

void die(const char *msg, ...) __attribute__((noreturn));

/**
 * malloc with checking for windows code.
 */
LPVOID wmalloc(ULONG size)
{
  void *p = malloc(size);
  if (p)
  {
    return p;
  }
  die("Unable to allocate %d bytes of memory", size);
}

/**
 * realloc with checking for windows code.
 */
LPVOID wrealloc(void *ptr, ULONG size)
{
  void *p = realloc(ptr, size);
  if (p)
  {
    return p;
  }
  die("Unable to allocate %d bytes of memory", size);
}
