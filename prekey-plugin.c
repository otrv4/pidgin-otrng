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

static void notify_error_cb(int error, void *ctx) {
  printf("prekey server: an error happened\n");
}

static void
storage_status_received_cb(const otrng_prekey_storage_status_message_s *msg,
                           void *ctx) {
  printf("prekey server: we still have %d prekeys stored\n",
         msg->stored_prekeys);
}

static void success_received_cb(void *ctx) {
  printf("prekey server: received success\n");
}

static void no_prekey_in_storage_received_cb(void *ctx) {
  printf("prekey server: there are no prekey in storage for the requested "
         "recipient\n");
}

static void
prekey_ensembles_received_cb(prekey_ensemble_s *const *const ensembles,
                             uint8_t num_ensembles, void *ctx) {
  printf("prekey server: we received %d ensembles\n", num_ensembles);
}

static otrng_prekey_client_callbacks_s prekey_client_cb = {
    .ctx = NULL,
    .notify_error = notify_error_cb,
    .storage_status_received = storage_status_received_cb,
    .success_received = success_received_cb,
    .no_prekey_in_storage_received = no_prekey_in_storage_received_cb,
    .prekey_ensembles_received = prekey_ensembles_received_cb,
};

static otrng_prekey_client_s *
otrng_plugin_get_prekey_client(PurpleAccount *account) {
  otrng_client_s *client = otrng_messaging_client_get(otrng_userstate, account);
  if (!client) {
    return NULL;
  }

  return otrng_client_get_prekey_client(prekeys_server_identity,
                                        &prekey_client_cb, client);
}

static gboolean
otrng_plugin_receive_prekey_protocol_message(char **tosend, const char *server,
                                             const char *message,
                                             PurpleAccount *account) {
  otrng_prekey_client_s *prekey_client = NULL;

  prekey_client = otrng_plugin_get_prekey_client(account);
  if (!prekey_client) {
    return FALSE;
  }

  return otrng_prekey_client_receive(tosend, server, message, prekey_client);
}

static void send_message(PurpleAccount *account, const char *recipient,
                         const char *message) {
  PurpleConnection *connection = purple_account_get_connection(account);
  if (!connection) {
    // Not connected
    return;
  }

  // TODO: Should this send to the original recipient or to the normalized
  // recipient?
  serv_send_im(connection, recipient, message, 0);
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
  message = otrng_prekey_client_retrieve_prekeys("bob@localhost", "45",
                                                 prekey_client);

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
