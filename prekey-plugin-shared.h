/*
 *  Off-the-Record Messaging plugin for pidgin
 *  Copyright (C) 2004-2018  Ian Goldberg, Rob Smits,
 *                           Chris Alexander, Willy Lew,
 *                           Nikita Borisov
 *                           <otr@cypherpunks.ca>
 *                           The pidgin-otrng contributors
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of version 2 of the GNU General Public License as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef OTRNG_PIDGIN_PREKEY_PLUGIN_SHARED
#define OTRNG_PIDGIN_PREKEY_PLUGIN_SHARED

#include <prpl.h>

#include <libotr-ng/client.h>
#include <libotr-ng/prekey_client.h>

typedef void (*WithPrekeyClient)(PurpleAccount *, otrng_client_s *,
                                 xyz_otrng_prekey_client_s *, void *);

typedef struct {
  PurpleAccount *account;
  otrng_client_s *client;
  int found;
  WithPrekeyClient next;
  void *ctx;
} lookup_prekey_server_for_prekey_client_ctx_s;

void otrng_plugin_get_prekey_client(PurpleAccount *account, WithPrekeyClient cb,
                                    void *uctx);
void trigger_potential_publishing(otrng_client_s *client);

void send_message(PurpleAccount *account, const char *recipient,
                  const char *message);

#endif // OTRNG_PIDGIN_PREKEY_PLUGIN_SHARED
