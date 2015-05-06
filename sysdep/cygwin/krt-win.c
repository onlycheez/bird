/*
 *	BIRD -- Windows Routing Table Syncing
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "nest/bird.h"
#include "nest/route.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "lib/krt.h"
#include "libwin/libwin.h"
#include "libwin/wstructs.h"

void
kif_sys_start(struct kif_proto *p UNUSED)
{

}

void
kif_sys_shutdown(struct kif_proto *p)
{

}

static struct iface* wstruct_convert_iface(struct wiface *wif)
{
  struct iface *f = xmalloc(sizeof(struct iface));
  memset(f, 0, sizeof(struct iface));
  memset(f->name, 0, sizeof(f->name));

  memcpy(f->name, wif->name, strlen(wif->name));
  f->index = (unsigned)wif->index;
  f->mtu = (unsigned)wif->mtu;


  // TODO: Setting flags.
  if (!(wif->flags & 0x10))
  {
    f->flags |= IF_MULTICAST;
  }

  if (wif->oper_status == 1)
  {
    f->flags |= IF_UP;
    f->flags |= IF_ADMIN_UP;
  }
  else if (wif->oper_status == 7)
  {
  }

  return f;
}

void
kif_do_scan(struct kif_proto *p UNUSED)
{
  struct wiface *wif;
  struct iface *f;

  if_start_update();

#ifdef IPV6
  win_if_scan(6);
#else
  win_if_scan(4);
#endif

  while (wif = win_if_next())
  {
    printf("wif index: %lu\n", wif->index);
    printf("wif name: %s\n", wif->name);
    printf("wif mtu: %lu\n", wif->mtu);

    f = wstruct_convert_iface(wif);
    free(wif->name);
    free(wif);

    if_update(f);
    // TODO: Delete removed interfaces
  }

  if_end_update();
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
