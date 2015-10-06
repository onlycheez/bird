#!/bin/bash

rm -f obj/lib/krt-win.{c,o} && cp sysdep/cygwin/krt-win.c obj/lib && make > /dev/null
