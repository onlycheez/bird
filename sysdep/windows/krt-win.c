/*
 *	BIRD -- Windows Routing Table Syncing
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "nest/route.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "lib/krt.h"

void
kif_sys_start(struct kif_proto *p UNUSED)
{

}

void
kif_sys_shutdown(struct kif_proto *p)
{

}

void
kif_do_scan(struct kif_proto *p UNUSED)
{

}

void
krt_sys_start(struct krt_proto *p)
{

}

void
krt_sys_shutdown(struct krt_proto *p UNUSED)
{

}

void
krt_do_scan(struct krt_proto *p UNUSED)	/* CONFIG_ALL_TABLES_AT_ONCE => p is NULL */
{

}

void
krt_replace_rte(struct krt_proto *p, net *n, rte *new, rte *old, struct ea_list *eattrs)
{

}

int
krt_sys_reconfigure(struct krt_proto *p UNUSED, struct krt_config *n, struct krt_config *o)
{
  return 1;
}

int
krt_capable(rte *e)
{
  return 1;
}

void
krt_sys_init_config(struct krt_config *cf)
{

}

void
krt_sys_copy_config(struct krt_config *d, struct krt_config *s)
{

}

void
krt_sys_postconfig(struct krt_config *x)
{

}

void
krt_sys_preconfig(struct config *c UNUSED)
{

}
