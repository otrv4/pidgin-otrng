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

#ifndef OTRNG_PIDGIN_PREKEY_PLUGIN_ACCOUNT
#define OTRNG_PIDGIN_PREKEY_PLUGIN_ACCOUNT

#include <glib.h>
#include <prpl.h>

#define PREKEYS_FILE_NAME "otr4.prekey_messages"

#include <libotr-ng/client.h>
#include <libotr-ng/prekey_client.h>

void low_prekey_messages_in_storage_cb(otrng_client_s *client,
                                       char *server_identity, void *ctx);
void storage_status_received_cb(
    otrng_client_s *client, const otrng_prekey_storage_status_message_s *msg,
    void *ctx);
void success_received_cb(otrng_client_s *client, void *ctx);
void failure_received_cb(otrng_client_s *client, void *ctx);
int build_prekey_publication_message_cb(
    otrng_client_s *client, otrng_prekey_publication_message_s *msg,
    otrng_prekey_publication_policy_s *policy, void *ctx);

gboolean otrng_prekey_plugin_account_load(PurplePlugin *handle);
gboolean otrng_prekey_plugin_account_unload(PurplePlugin *handle);

#endif // OTRNG_PIDGIN_PREKEY_PLUGIN_ACCOUNT
