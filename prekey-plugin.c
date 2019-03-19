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

#include "prekey-plugin.h"
#include "prekey-plugin-account.h"
#include "prekey-plugin-peers.h"
#include "prekey-plugin-shared.h"

/* If we're using glib on Windows, we need to use g_fopen to open files.
 * On other platforms, it's also safe to use it.  If we're not using
 * glib, just use fopen. */
#ifdef USING_GTK
/* If we're cross-compiling, this might be wrong, so fix it. */
#ifdef WIN32
#undef G_OS_UNIX
#define G_OS_WIN32
#endif
#include <glib/gstdio.h>
#else
#define g_fopen fopen
#endif

#ifdef ENABLE_NLS
/* internationalisation header */
#include <glib/gi18n-lib.h>
#else
#define _(x) (x)
#define N_(x) (x)
#endif

/* libpurple */
#include <connection.h>
#include <prpl.h>

#include <libotr-ng/alloc.h>
#include <libotr-ng/client_orchestration.h>
#include <libotr-ng/debug.h>
#include <libotr-ng/deserialize.h>
#include <libotr-ng/messaging.h>

#include "pidgin-helpers.h"
#include "prekey-discovery.h"

extern otrng_global_state_s *otrng_state;

static void notify_error_cb(otrng_client_s *client, int error, void *ctx) {
  otrng_debug_fprintf(stderr, "[%s] Prekey Server: an error happened: %d\n",
                      client->client_id.account, error);
}

xyz_otrng_prekey_client_callbacks_s prekey_client_cb = {
    .ctx = NULL,
    .notify_error = notify_error_cb,
    .storage_status_received = storage_status_received_cb,
    .success_received = success_received_cb,
    .failure_received = failure_received_cb,
    .no_prekey_in_storage_received = no_prekey_in_storage_received_cb,
    .low_prekey_messages_in_storage = low_prekey_messages_in_storage_cb,
    .prekey_ensembles_received = prekey_ensembles_received_cb,
    .build_prekey_publication_message = build_prekey_publication_message_cb,
};

static gboolean
otrng_plugin_receive_prekey_protocol_message(char **tosend, const char *server,
                                             const char *message,
                                             PurpleAccount *account) {
  otrng_client_s *client =
      otrng_client_get(otrng_state, purple_account_to_client_id(account));
  if (!client || !client->prekey_client) {
    return FALSE;
  }

  return xyz_otrng_prekey_client_receive(tosend, server, message, client);
}

static gboolean receiving_im_msg_cb(PurpleAccount *account, char **who,
                                    char **message, PurpleConversation *conv,
                                    PurpleMessageFlags *flags) {

  if (!who || !*who || !message || !*message) {
    return 0;
  }

  char *username = g_strdup(purple_normalize(account, *who));

  char *tosend = NULL;
  gboolean ignore = otrng_plugin_receive_prekey_protocol_message(
      &tosend, username, *message, account);
  free(username);

  if (tosend) {
    send_message(account, *who, tosend);
    free(tosend);
  }

  // We consumed the message
  if (ignore) {
    free(*message);
    *message = NULL;
  }

  return ignore;
}

gboolean otrng_prekey_plugin_load(PurplePlugin *handle) {
  if (!otrng_state) {
    return FALSE;
  }

  /* Process received prekey protocol messages */
  purple_signal_connect(purple_conversations_get_handle(), "receiving-im-msg",
                        handle, PURPLE_CALLBACK(receiving_im_msg_cb), NULL);

  otrng_prekey_plugin_account_load(handle);
  otrng_prekey_plugin_peers_load(handle);

  // Do the same on the already connected accounts
  // GList *connections = purple_connections_get_all();
  return TRUE;
}

gboolean otrng_prekey_plugin_unload(PurplePlugin *handle) {
  otrng_prekey_plugin_peers_unload(handle);
  otrng_prekey_plugin_account_unload(handle);

  purple_signal_disconnect(purple_conversations_get_handle(),
                           "receiving-im-msg", handle,
                           PURPLE_CALLBACK(receiving_im_msg_cb));

  return TRUE;
}
