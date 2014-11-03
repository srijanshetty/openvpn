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

#ifdef ENABLE_MFA
#define MAX_MFA_SESSIONS 128
#define MFA_TOKEN_LENGTH 65
#define MFA_COOKIE_IV_LENGTH 128
#define MFA_TIMESTAMP_LENGTH 20
struct mfa_session_info
{
  char *cn;
  char *token;
  unsigned char *remote_address;
  char *timestamp;
};

struct mfa_session_store
{
  int len;
  struct mfa_session_info *mfa_session_info[MAX_MFA_SESSIONS];
};

struct mfa_session_info *
get_cookie (const struct openvpn_sockaddr *dest, struct mfa_session_store *store);

struct mfa_session_info *
create_cookie ();
#endif

#endif
