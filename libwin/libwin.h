
#include "wstructs.h"

/**
 * @param[in] ipv IP version.
 */
void win_if_scan(int ipv);

struct wiface* win_if_next(void);

int win_if_update_in_progess(void);
