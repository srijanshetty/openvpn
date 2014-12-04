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
struct mfa_session_info * get_cookie (const struct openvpn_sockaddr *dest, struct mfa_session_store *store)
{
  struct gc_arena gc = gc_new();
  int i;
  const char *addr = print_openvpn_sockaddr(dest, &gc);
  if (!addr)
    return NULL;
  for (i = 0; i < store->len; i++)
    {
      if (!strcmp(addr, store->mfa_session_info[i]->remote_address))
        {
          break;
        }
    }
  gc_free(&gc);
  if (i == store->len)
    return NULL;
  return store->mfa_session_info[i];
}

void generate_token(char * cn, char * timestamp, unint8_t * key, char *token)
{
  char *data;
  uint8_t hash;
  struct gc_arena gc = gc_new();
  int length = strlen(cn) + strlen(timestamp) + 1;

  ALLOC_ARRAY_CLEAR_GC (data, char, length, &gc);
  ALLOC_ARRAY_CLEAR_GC (hash, uint8_t, len_hash, &gc);

  openvpn_snprintf (data, length, "%s%s", cn, timestamp);
  tls1_PRF ((uint8_t) data, length-1, key, MFA_COOKIE_KEY_LENGTH, hash, MFA_COOKIE_HASH_LENGTH);

  char *hex = format_hex (k->random2, sizeof (k->random2), 0, &gc));
  memcpy(token, hex, MFA_COOKIE_HASH_LENGTH);
  gc_free(&gc);
}

void verify_cookie (struct tls_session *session, struct mfa_session_info *cookie)
{
  struct gc_arena gc = gc_new();
  char * generated_token;
  ALLOC_ARRAY_CLEAR_GC (generated_token, char, MFA_COOKIE_HASH_LENGTH, &gc);
  generate_token(session->common_name, cookie->timestamp, session->opt->cookie_key, generate_token);
  if(strcmp(cookie->token, generate_token) == 0)
    session->key[KEY_PRIMARY]->authenticated = true;
  else
    msg(D_TLS_ERRORS, "TLS_AUTH_ERROR: Cookie authentication failed");
  gc_free(&gc);
}
#endif
