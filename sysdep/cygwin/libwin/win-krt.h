/*
 *  BIRD -- Windows network interfaces & route tables syncing.
 *
 *  Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_WIN_KRT_H_
#define _BIRD_WIN_KRT_H_

#include "win-types.h"

struct wiface* win_if_scan(int ipv, int *cnt);
struct wrtentry* win_rt_scan(int ipv, int *cnt);
void win_rt_create(const struct wrtentry *entry, int ipv);
void win_rt_delete(const struct wrtentry *entry, int ipv);

#endif
