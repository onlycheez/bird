
#include "wstructs.h"

/**
 * @param[in] ipv IP version.
 */
struct wiface* win_if_scan(int ipv, int *cnt);
struct wrtentry* win_rt_scan(int ipv, int *cnt);
