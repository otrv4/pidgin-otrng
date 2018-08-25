#include "prekey-plugin.h"

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

#include <libotr-ng/deserialize.h>
#include <libotr-ng/messaging.h>

extern otrng_user_state_s *otrng_userstate;

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

// TODO: Query the server from service discovery and fallback to
//"prekeys.<domainpart>" server.
#ifdef DEFAULT_PREKEYS_SERVER
static const char *prekeys_server_identity = DEFAULT_PREKEYS_SERVER;
#else
static const char *prekeys_server_identity = "";
#endif

static void notify_error_cb(int error, void *ctx) {
  printf("\nPrekey Server: an error happened: %d \n", error);
}

static void
storage_status_received_cb(const otrng_prekey_storage_status_message_s *msg,
                           void *ctx) {
  printf("\nPrekey Server: we have %d prekey messages stored.\n",
         msg->stored_prekeys);
}

static void success_received_cb(void *ctx) {
  printf("\nPrekey Server: received success\n");
}

static void failure_received_cb(void *ctx) {
  printf("\nPrekey Server: something happened. We were unable to process the "
         "request.\n");
}

static void no_prekey_in_storage_received_cb(void *ctx) {
  printf("\nPrekey Server: there are no prekey in storage for the requested "
         "recipient.\n");
}

static void low_prekey_messages_in_storage_cb(char *server_identity,
                                              void *ctx) {
  printf("\nPrekey Server: Publishing prekey messages.\n");

  PurpleAccount *account = ctx;

  PurpleConnection *connection = purple_account_get_connection(account);
  if (!connection) {
    printf("\n No connection \n");
    // Not connected
    return;
  }

  otrng_prekey_client_s *prekey_client =
      otrng_plugin_get_prekey_client(account);
  if (!prekey_client) {
    printf("\n No prekey client \n");
    return;
  }

  char *message = NULL;
  message = otrng_prekey_client_publish_prekeys(prekey_client);

  serv_send_im(connection, server_identity, message, 0);
}

static void send_offline_messages_to_each_ensemble(
    prekey_ensemble_s *const *const ensembles, uint8_t num_ensembles,
    otrng_plugin_offline_message_ctx *ctx) {

  PurpleAccount *account = ctx->account;
  const char *message = ctx->message;
  const char *recipient = ctx->recipient;

  otrng_client_s *client = otrng_messaging_client_get(otrng_userstate, account);
  if (!client) {
    return;
  }

  int i;
  for (i = 0; i < num_ensembles; i++) {
    if (!otrng_prekey_ensemble_validate(ensembles[i])) {
      printf("The Prekey Ensemble %d is not valid\n", i);
      continue;
    }

    char *to_send = NULL;
    if (otrng_client_send_non_interactive_auth(&to_send, ensembles[i],
                                               recipient, client)) {
      // TODO: error
      continue;
    }

    send_message(account, recipient, to_send);
    free(to_send);

    if (otrng_client_send(&to_send, message, recipient, client)) {
      // TODO: error
      continue;
    }

    send_message(account, recipient, to_send);
    free(to_send);
  }

  // 1. Build a offline message for each received ensemble
  // 2. Send each message through the network
  // 3. Send a single query message (dependencia na outra direção).
}

static void
prekey_ensembles_received_cb(prekey_ensemble_s *const *const ensembles,
                             uint8_t num_ensembles, void *ctx) {
  printf("\nPrekey Server: we received %d ensembles.\n", num_ensembles);

  if (!ctx) {
    printf("\n Invalid NULL context\n");
  }

  otrng_plugin_offline_message_ctx *c = ctx;

  send_offline_messages_to_each_ensemble(ensembles, num_ensembles, c);

  // TODO: this can be causing the crash
  free(c->message);
  free(c->recipient);
  free(c);
}

#define PREKEYSFNAME "otr4.prekey_messages"

static int
build_prekey_publication_message_cb(otrng_prekey_publication_message_s *msg,
                                    void *ctx) {
  if (!ctx) {
    printf("received invalid ctx\n");
    return 0;
  }

  FILE *privf = NULL;
  gchar *prekeysfile = g_build_filename(purple_user_dir(), PREKEYSFNAME, NULL);
  if (!prekeysfile) {
    fprintf(stderr, _("Out of memory building filenames!\n"));
    return 0;
  }

  privf = g_fopen(prekeysfile, "w+b");
  g_free(prekeysfile);

#ifndef WIN32
  mode_t mask = umask(0077);
  umask(mask);
#endif /* WIN32 */

  if (!privf) {
    fprintf(stderr, _("Could not write prekey messages file\n"));
    return 0;
  }

  PurpleAccount *account = ctx;

  otrng_client_s *client = otrng_messaging_client_get(otrng_userstate, account);
  if (!client) {
    return 0;
  }

  msg->num_prekey_messages = 5; // TODO: how is this chosen?
  msg->prekey_messages =
      otrng_client_build_prekey_messages(msg->num_prekey_messages, client);

  if (!msg->prekey_messages) {
    return 0;
  }

  const client_profile_s *client_profile =
      otrng_client_state_get_client_profile(client->state);
  const otrng_prekey_profile_s *prekey_profile =
      otrng_client_state_get_prekey_profile(client->state);

  // TODO: only publish when needed.
  msg->client_profile = malloc(sizeof(client_profile_s));
  otrng_client_profile_copy(msg->client_profile, client_profile);

  msg->prekey_profile = malloc(sizeof(otrng_prekey_profile_s));
  otrng_prekey_profile_copy(msg->prekey_profile, prekey_profile);

  otrng_user_state_prekey_messages_write_FILEp(otrng_userstate, privf);
  fclose(privf);
  return 1;
}

static otrng_prekey_client_callbacks_s prekey_client_cb = {
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

otrng_prekey_client_s *otrng_plugin_get_prekey_client(PurpleAccount *account) {
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

  prekey_client->callbacks->ctx = account;

  message = otrng_prekey_client_request_storage_information(prekey_client);

  // 1. Publish prekeys
  // message = otrng_prekey_client_publish_prekeys(prekey_client);

  // 2. Retrieve the status of storage for yourself
  // message = otrng_prekey_client_request_storage_information(prekey_client);

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
