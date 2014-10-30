/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include "mfa_session.h"
#include "socket.h"

#ifdef ENABLE_MFA
struct mfa_session_info * get_cookie (const openvpn_sockaddr *dest, struct mfa_session_store *store)
{
  struct gc_arena gc = gc_new();
  int i;
  char *addr = print_openvpn_sockaddr(dest, &gc);
  if (!addr)
    return NULL;
  for (i = 0; i < store->len; i++)
    {
      if (streq(addr, store->mfa_session_info[i]->remote_address))
        {
          break;
        }
    }
  gc_free(&gc);
  if (i == store->len)
    return NULL;
  return store->mfa_session_info[i];
}
#endif
