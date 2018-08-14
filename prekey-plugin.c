#include "prekey-plugin.h"

/* libpurple */
#include <connection.h>
#include <prpl.h>

#include <libotr-ng/deserialize.h>
#include <libotr-ng/messaging.h>

extern otrng_user_state_s *otrng_userstate;

// TODO: Query the server from service discovery and fallback to
//"prekeys.<domainpart>" server.
#ifdef DEFAULT_PREKEYS_SERVER
static const char *prekeys_server_identity = DEFAULT_PREKEYS_SERVER;
#else
static const char *prekeys_server_identity = "";
#endif

otrng_prekey_client_s *otrng_plugin_get_prekey_client(PurpleAccount *account) {
  otrng_client_s *client = otrng_messaging_client_get(otrng_userstate, account);
  if (!client) {
    return NULL;
  }

  return otrng_client_get_prekey_client(prekeys_server_identity, client);
}

gboolean otrng_plugin_receive_prekey_protocol_message(char **tosend,
                                                      const char *server,
                                                      const char *message,
                                                      PurpleAccount *account) {
  otrng_prekey_client_s *prekey_client = NULL;

  prekey_client = otrng_plugin_get_prekey_client(account);
  if (!prekey_client) {
    return FALSE;
  }

  return otrng_prekey_client_receive(tosend, server, message, prekey_client);
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
    // TODO: Should this send to the original who or to the normalized who?
    otrng_plugin_inject_message(account, *who, tosend);
    free(tosend);
  }

  // We consumed the message
  free(*message);
  *message = NULL;

  return ignore;
}

static void account_signed_on_cb(PurpleConnection *conn, void *data) {
  PurpleAccount *account = purple_connection_get_account(conn);
  char *message = NULL;

  otrng_prekey_client_s *prekey_client =
      otrng_plugin_get_prekey_client(account);
  if (!prekey_client) {
    return;
  }

  // 1. Publish prekeys
  //  message = otrng_prekey_client_publish_prekeys(prekey_client);

  // 2. Retrieve the status of storage for yourself
  // message = otrng_prekey_client_request_storage_status(prekey_client);

 // 3. Retrieve prekey ensembles for us 
  message = otrng_prekey_client_retrieve_prekeys("bob@localhost", "45", prekey_client);

  serv_send_im(conn, prekey_client->server_identity, message, 0);
  free(message);
}

gboolean otrng_prekey_plugin_load(PurplePlugin *handle) {
  if (!otrng_userstate) {
    return FALSE;
  }

  /* Watch to the connect event of every account */
  purple_signal_connect(purple_connections_get_handle(), "signed-on", handle,
                        PURPLE_CALLBACK(account_signed_on_cb), NULL);

  /* Process received prekey protocol messages */
  purple_signal_connect(purple_conversations_get_handle(), "receiving-im-msg",
                        handle, PURPLE_CALLBACK(receiving_im_msg_cb), NULL);

  // Do the same on the already connected accounts
  // GList *connections = purple_connections_get_all();
  return TRUE;
}

gboolean otrng_prekey_plugin_unload(PurplePlugin *handle) {

  purple_signal_disconnect(purple_conversations_get_handle(),
                           "receiving-im-msg", handle,
                           PURPLE_CALLBACK(receiving_im_msg_cb));

  purple_signal_disconnect(purple_connections_get_handle(), "signed-on", handle,
                           PURPLE_CALLBACK(account_signed_on_cb));
  return TRUE;
}
