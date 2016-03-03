
#include "win-types.h"

/**
 * @param[in] ipv IP version.
 */
struct wiface* win_if_scan(int ipv, int *cnt);
struct wrtentry* win_rt_scan(int ipv, int *cnt);
void win_rt_create(struct wrtentry *entry, int ipv);
void win_rt_delete(struct wrtentry *entry, int ipv);
