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

#include "prekey-plugin-account.h"
#include "prekey-plugin-shared.h"

#include <libotr-ng/alloc.h>
#include <libotr-ng/client_orchestration.h>
#include <libotr-ng/debug.h>
#include <libotr-ng/deserialize.h>
#include <libotr-ng/messaging.h>

#include "pidgin-helpers.h"
#include "prekey-discovery.h"

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

extern otrng_global_state_s *otrng_state;

void storage_status_received_cb(
    otrng_client_s *client, const otrng_prekey_storage_status_message_s *msg,
    void *ctx) {
  otrng_debug_fprintf(
      stderr, "[%s] Prekey Server: we have %d prekey messages stored.\n",
      client->client_id.account, msg->stored_prekeys);
}

void success_received_cb(otrng_client_s *client, void *ctx) {
  otrng_client_published(client);
  client->prekey_msgs_num_to_publish = 0;
  otrng_debug_fprintf(stderr, "[%s] Prekey Server: received success\n",
                      client->client_id.account);
}

void failure_received_cb(otrng_client_s *client, void *ctx) {
  otrng_client_failed_published(client);
  otrng_debug_fprintf(
      stderr,
      "[%s] Prekey Server: something happened. We were unable to process the "
      "request.\n",
      client->client_id.account);
}

static void publishing_after_server_identity(PurpleAccount *account,
                                             otrng_client_s *client,
                                             void *ctx) {
  otrng_debug_enter("publishing_after_server_identity");
  PurpleConnection *connection = purple_account_get_connection(account);
  if (!connection) {
    otrng_debug_fprintf(stderr, "No connection. \n");
    otrng_debug_exit("publishing_after_server_identity");
    return;
  }

  char *message = NULL;
  otrng_client_start_publishing(client);

  // TODO: deal with errors here
  otrng_prekey_publish(&message, client, ctx);

  char *domain = otrng_plugin_prekey_domain_for(
      account, purple_account_get_username(account));
  otrng_prekey_server_s *si =
      otrng_prekey_get_server_identity_for(client, domain);
  g_free(domain);

  serv_send_im(connection, si->identity, message, 0);
  otrng_debug_exit("publishing_after_server_identity");
}

void low_prekey_messages_in_storage_cb(otrng_client_s *client, void *ctx) {
  otrng_debug_enter("low_prekey_messages_in_storage_cb");
  otrng_client_ensure_correct_state(client);
  trigger_potential_publishing(client);
  otrng_debug_exit("low_prekey_messages_in_storage_cb");
}

int build_prekey_publication_message_cb(otrng_client_s *client,
                                        otrng_prekey_publication_message_s *msg,
                                        void *ctx) {
  otrng_debug_enter("build_prekey_publication_message_cb");

  otrng_client_ensure_correct_state(client);

  otrng_prekey_add_prekey_messages_for_publication(client, msg);

  if (msg->num_prekey_messages > 0) {
    otrng_debug_fprintf(stderr,
                        "[%s] Prekey Server: Publishing %d Prekey Messages\n",
                        client->client_id.account, msg->num_prekey_messages);
  }

  otrng_client_profile_s *client_profile =
      otrng_client_get_client_profile(client);
  if (otrng_client_profile_should_publish(client_profile)) {
    otrng_client_profile_start_publishing(client_profile);

    otrng_debug_fprintf(stderr,
                        "[%s] Prekey Server: Publishing Client Profile\n",
                        client->client_id.account);
    msg->client_profile = otrng_xmalloc_z(sizeof(otrng_client_profile_s));
    otrng_client_profile_copy(msg->client_profile, client_profile);
  }

  otrng_prekey_profile_s *prekey_profile =
      otrng_client_get_prekey_profile(client);
  if (otrng_prekey_profile_should_publish(prekey_profile)) {
    otrng_prekey_profile_start_publishing(prekey_profile);

    otrng_debug_fprintf(stderr,
                        "[%s] Prekey Server: Publishing Prekey Profile\n",
                        client->client_id.account);
    msg->prekey_profile = otrng_xmalloc_z(sizeof(otrng_prekey_profile_s));
    otrng_prekey_profile_copy(msg->prekey_profile, prekey_profile);
  }

  otrng_debug_exit("build_prekey_publication_message_cb");
  return 1;
}

static void account_signed_on_after_server_identity(PurpleAccount *account,
                                                    otrng_client_s *client,
                                                    void *ctx) {
  otrng_debug_enter("account_signed_on_after_server_identity");
  char *message = NULL;

  PurpleConnection *connection = purple_account_get_connection(account);
  if (!connection) {
    otrng_debug_fprintf(stderr, "No connection. \n");
    otrng_debug_exit("account_signed_on_after_server_identity");
    return;
  }
  otrng_client_ensure_correct_state(client);

  // TODO: handle error here
  otrng_prekey_request_storage_information(&message, client, account);

  char *domain = otrng_plugin_prekey_domain_for(
      account, purple_account_get_username(account));
  otrng_prekey_server_s *si =
      otrng_prekey_get_server_identity_for(client, domain);
  g_free(domain);

  // TODO: we should probably set some Purple flags on this call, instead of the
  // 0
  serv_send_im(connection, si->identity, message, 0);
  free(message);
  otrng_debug_exit("account_signed_on_after_server_identity");
}

static void account_signed_on_cb(PurpleConnection *conn, void *data) {
  otrng_debug_enter("account_signed_on_cb");
  PurpleAccount *account = purple_connection_get_account(conn);
  otrng_plugin_ensure_server_identity(
      account, purple_account_get_username(account),
      account_signed_on_after_server_identity, NULL);
  otrng_debug_exit("account_signed_on_cb");
}

static void maybe_publish_prekey_data(void *client_pre, void *ignored) {
  (void)ignored;
  otrng_client_s *client = client_pre;
  otrng_debug_enter("maybe_publish_prekey_data");
  otrng_debug_fprintf(stderr, "client=%s\n", client->client_id.account);

  if (!otrng_client_should_publish(client)) {
    otrng_debug_exit("maybe_publish_prekey_data");
    return;
  }
  otrng_debug_fprintf(stderr, "Prekey: we have been asked to publish...\n");
  PurpleAccount *account = client_id_to_purple_account(client->client_id);
  otrng_plugin_ensure_server_identity(
      account, purple_account_get_username(account),
      publishing_after_server_identity, account);
  otrng_debug_exit("maybe_publish_prekey_data");
}

gboolean otrng_prekey_plugin_account_load(PurplePlugin *handle) {
  purple_signal_register(handle, "maybe-publish-prekey-data",
                         purple_marshal_VOID__POINTER, NULL, 1,
                         purple_value_new(PURPLE_TYPE_POINTER));

  /* Watch to the connect event of every account */
  purple_signal_connect(purple_connections_get_handle(), "signed-on", handle,
                        PURPLE_CALLBACK(account_signed_on_cb), NULL);

  purple_signal_connect(handle, "maybe-publish-prekey-data", handle,
                        PURPLE_CALLBACK(maybe_publish_prekey_data), NULL);

  return TRUE;
}

gboolean otrng_prekey_plugin_account_unload(PurplePlugin *handle) {

  purple_signal_disconnect(handle, "maybe-publish-prekey-data", handle,
                           PURPLE_CALLBACK(maybe_publish_prekey_data));

  purple_signal_disconnect(purple_connections_get_handle(), "signed-on", handle,
                           PURPLE_CALLBACK(account_signed_on_cb));

  purple_signal_unregister(handle, "maybe-publish-prekey-data");

  return TRUE;
}
