#!/bin/sh

LIBSOURCES="cf-lex.l conf.c conf.h"

for LIBSOURCE in $LIBSOURCES; do
  rm "obj/conf/${LIBSOURCE}"
  cp "conf/${LIBSOURCE}" "obj/conf/${LIBSOURCE}"
done

LIBSOURCES="timer.h endian.h unix.h log.c io.c sysio.h random.c missing.h krt.h krt.c krt-sys.h main.c krt-win.c"

for LIBSOURCE in $LIBSOURCES; do
  rm "obj/lib/${LIBSOURCE}"
  cp "sysdep/windows/${LIBSOURCE}" "obj/lib/${LIBSOURCE}"
done

LIBSOURCES="alloca.h birdlib.h bitops.c bitops.h buffer.h checksum.c checksum.h event.c event.h hash.h heap.h ip.c ip.h ipv4.c ipv4.h ipv6.c ipv6.h lists.c lists.h md5.c md5.h mempool.c patmatch.c printf.c resource.c resource.h slab.c slists.c slists.h socket.h string.h tbf.c unaligned.h xmalloc.c"

for LIBSOURCE in $LIBSOURCES; do
  rm "obj/lib/${LIBSOURCE}"
  cp "lib/${LIBSOURCE}" "obj/lib/${LIBSOURCE}"
done
