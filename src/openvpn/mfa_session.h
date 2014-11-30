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

/**
 * @file Module to handle sessions for MFA
 */

#ifndef MFA_SESSION_H
#define MFA_SESSION_H

#include "socket.h"
#include "ssl_common.h"
#include "ssl_verify.h"

#ifdef ENABLE_MFA
#define MAX_SESSION_VALIDITY 100000
#define MAX_MFA_SESSIONS 1024
#define MFA_TOKEN_LENGTH 66
#define MFA_COOKIE_KEY_LENGTH 48  /* in bytes */
#define MFA_COOKIE_HASH_LENGTH 32
#define MFA_TIMESTAMP_LENGTH 20
#define REMOTE_ADDRESS_LENGTH 64

struct mfa_session_info
{
  char token[MFA_TOKEN_LENGTH];
  char remote_address[REMOTE_ADDRESS_LENGTH];
  char timestamp[MFA_TIMESTAMP_LENGTH];
};

struct mfa_session_store
{
  int len;
  struct mfa_session_info *mfa_session_info[MAX_MFA_SESSIONS];
};

void
update_cookie_file (struct mfa_session_info *cookie, char * cookie_file, struct openvpn_sockaddr *dest);

struct mfa_session_info *
get_cookie (const struct openvpn_sockaddr *dest, struct gc_arena *gc, char *cookie_file);

void
create_cookie (struct tls_session *session, struct mfa_session_info *cookie);

void
verify_cookie (struct tls_session *session, struct mfa_session_info *cookie);
#endif

#endif
