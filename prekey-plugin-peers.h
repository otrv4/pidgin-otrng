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

#ifndef OTRNG_PIDGIN_PREKEY_PLUGIN_PEERS
#define OTRNG_PIDGIN_PREKEY_PLUGIN_PEERS

#include <glib.h>
#include <prpl.h>

#include <libotr-ng/client.h>

void otrng_prekey_plugin_add_to_mapped_prekey_ensembles_responses(
    const otrng_client_s *client, PurpleAccount *account, char *message,
    char *recipient);
void no_prekey_in_storage_received_cb(otrng_client_s *client,
                                      const char *identity);
void prekey_ensembles_received_cb(otrng_client_s *client,
                                  prekey_ensemble_s *const *const ensembles,
                                  uint8_t num_ensembles, const char *identity);

gboolean otrng_prekey_plugin_peers_load(PurplePlugin *handle);
gboolean otrng_prekey_plugin_peers_unload(PurplePlugin *handle);

#endif // OTRNG_PIDGIN_PREKEY_PLUGIN_PEERS
