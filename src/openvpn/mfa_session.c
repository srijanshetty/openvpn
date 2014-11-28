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
#include "otime.h"

#ifdef ENABLE_MFA
void
mfa_session_read (struct mfa_session_store *cookie_jar, char *cookie_file, struct gc_arena *gc)
{
  if (cookie_jar && cookie_file)
    {
      struct status_output * file = status_open (cookie_file, 0, -1, NULL, STATUS_OUTPUT_READ);
      struct gc_arena local_gc = gc_new ();
      struct buffer in = alloc_buf_gc (REMOTE_ADDRESS_LENGTH + MFA_TOKEN_LENGTH + MFA_TIMESTAMP_LENGTH, &local_gc);
      int line = 0;
      cookie_jar->len = 0;


      while (true)
	{
	  ASSERT (buf_init (&in, 0));
	  if (!status_read (file, &in))
	    break;
	  ++line;
	  if (BLEN (&in))
	    {
	      int c = *BSTR(&in);

              struct mfa_session_info *cookie;
              ALLOC_OBJ_CLEAR_GC (cookie, struct mfa_session_info, gc);
	      if (buf_parse (&in, ',', cookie->remote_address, REMOTE_ADDRESS_LENGTH)
		  && buf_parse (&in, ',', cookie->token, MFA_TOKEN_LENGTH)
		  && buf_parse (&in, ',', cookie->timestamp, MFA_TIMESTAMP_LENGTH))
		{
                  cookie_jar->mfa_session_info[cookie_jar->len] = cookie;
                  cookie_jar->len++;
                  if(cookie_jar->len == MAX_MFA_SESSIONS)
                    {
                      msg(M_INFO, "Number of session tokens in mfa-session file exceeds the maximum of %d", MAX_MFA_SESSIONS);
                      break;
                    }
		}
	    }
	}
      status_close(file);
      CLEAR(in);
      gc_free (&local_gc);
    }
}

void
update_cookie_file (struct mfa_session_info *cookie, char * cookie_file, struct openvpn_sockaddr *dest)
{
  struct mfa_session_store *cookie_jar;
  struct gc_arena gc = gc_new();
  ALLOC_OBJ_CLEAR_GC(cookie_jar, struct mfa_session_store, &gc);
  mfa_session_read (cookie_jar, cookie_file, &gc);
  const char * remote_address = print_openvpn_sockaddr (dest, &gc);
  struct status_output * file = status_open (cookie_file, 0, -1, NULL, STATUS_OUTPUT_WRITE);
  int i;
  bool write_current = false;
  for (i = 0; i < cookie_jar->len; i++)
    {
      struct mfa_session_info * current_cookie = cookie_jar->mfa_session_info[i];
      if (strcmp(current_cookie->remote_address, remote_address) == 0)
        {
          CLEAR(current_cookie->token);
          CLEAR(current_cookie->timestamp);
          memcpy(current_cookie->token, cookie->token, MFA_TOKEN_LENGTH);
          memcpy(current_cookie->timestamp, cookie->timestamp, MFA_TIMESTAMP_LENGTH);
          write_current = true;
        }
      status_printf(file, "%s,%s,%s",
                    current_cookie->remote_address,
                    current_cookie->token,
                    current_cookie->timestamp);
    }
  if (!write_current)
    {
      status_printf(file, "%s,%s,%s",
                    remote_address,
                    cookie->token,
                    cookie->timestamp);
    }
  status_close(file);
  CLEAR(cookie_jar);
  gc_free(&gc);
}


struct mfa_session_info * get_cookie (const struct openvpn_sockaddr *dest, struct gc_arena *gc, char *cookie_file)
{
  struct gc_arena local_gc = gc_new();
  struct mfa_session_store *cookie_jar;
  ALLOC_OBJ_CLEAR_GC (cookie_jar, struct mfa_session_store, &local_gc);
  mfa_session_read (cookie_jar, cookie_file, &local_gc);
  int i;
  struct mfa_session_info *correct_cookie;
  ALLOC_OBJ_CLEAR_GC(correct_cookie, struct mfa_session_info, gc);
  const char *addr = print_openvpn_sockaddr (dest, &local_gc);
  if (!addr)
    return NULL;
  for (i = 0; i < cookie_jar->len; i++)
    {
      if (!strcmp (addr, cookie_jar->mfa_session_info[i]->remote_address))
        {
          break;
        }
      else
        {
          CLEAR (cookie_jar->mfa_session_info[i]);
        }
    }
  if (i == cookie_jar->len)
    return NULL;
  *correct_cookie = *(cookie_jar->mfa_session_info[i]);
  gc_free(&local_gc);
  return correct_cookie;
}

void generate_token(char * common_name, char * timestamp, uint8_t * key, char *token)
{
  char *data;
  uint8_t *hash;
  struct gc_arena gc = gc_new();
  int length = strlen(common_name) + strlen(timestamp) + 1;

  ALLOC_ARRAY_CLEAR_GC (data, char, length, &gc);
  ALLOC_ARRAY_CLEAR_GC (hash, uint8_t, MFA_COOKIE_HASH_LENGTH, &gc);

  openvpn_snprintf (data, length, "%s%s", common_name, timestamp);
  mfa_PRF ((uint8_t *) data, length-1, key, MFA_COOKIE_KEY_LENGTH, hash, MFA_COOKIE_HASH_LENGTH);

  char *hex = format_hex_ex (hash, MFA_COOKIE_HASH_LENGTH, MFA_TOKEN_LENGTH, 100, NULL, &gc);
  memcpy(token, hex, MFA_TOKEN_LENGTH);

  gc_free(&gc);
}

void create_cookie (struct tls_session *session, struct mfa_session_info *cookie)
{
  struct timeval tv;
  gettimeofday (&tv, NULL);
  openvpn_snprintf (cookie->timestamp, MFA_TIMESTAMP_LENGTH, "%llu", (long long unsigned) tv.tv_sec);
  generate_token (session->common_name, cookie->timestamp, session->opt->cookie_key, cookie->token);
}

void verify_cookie (struct tls_session *session, struct mfa_session_info *cookie)
{
  struct gc_arena gc = gc_new();
  // Check if the cookie has expired or not
  struct timeval tv;
  struct timeval now;
  gettimeofday(&now, NULL);

  if (!parse_time_string(cookie->timestamp, &tv))      /* Timestamp parsing failed */
    goto error;

  /* Check for expiration */
  if (!tv_within_hours(&now, &tv, session->opt->mfa_session_expire))
    goto error;

  char * generated_token;
  ALLOC_ARRAY_CLEAR_GC (generated_token, char, MFA_TOKEN_LENGTH, &gc);
  generate_token (session->common_name, cookie->timestamp, session->opt->cookie_key, generated_token);

  if (strcmp(cookie->token, generated_token) == 0)
    {
      msg(M_INFO, "Cookie authentication successful");
      session->key[KS_PRIMARY].authenticated = true;
    }
  else
    goto error;

  gc_free(&gc);
  return;

 error:
  msg(D_TLS_ERRORS, "TLS_AUTH_ERROR: Cookie authentication failed");
  gc_free(&gc);
}

#endif
