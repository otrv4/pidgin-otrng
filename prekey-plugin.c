#include "prekey-plugin.h"

/* libpurple */
#include "account.h"
#include "connection.h"
#include "prpl.h"

#include <libotr-ng/messaging.h>

extern otrng_user_state_s *otrng_userstate;

static void account_signed_on_cb(PurpleConnection *conn, void *data) {
#ifdef DEFAULT_PREKEYS_SERVER
  const char *prekeys_server = DEFAULT_PREKEYS_SERVER;
#else
  const char *prekeys_server = "";
#endif

  PurpleAccount *account = purple_connection_get_account(conn);

  char *message = NULL;
  otrng_client_s *client = otrng_messaging_client_get(otrng_userstate, account);
  if (!client) {
    return;
  }
  otrng_prekey_client_s *prekey_client = otrng_client_get_prekey_client(client);

  if (!prekey_client) {
    return;
  }

  // otrng_xmpp_prekey_client_s *xmpp_client =
  // otrng_xmpp_prekey_client_new(prekeys_server, prekey_client); message =
  // otrng_xmpp_prekey_client_request_storage_status(xmpp_client); to_send =
  // otrng_xmpp_prekey_client_request_storage_status(xmpp_client);

  message = otrng_prekey_client_request_storage_status(prekey_client);
  serv_send_im(conn, prekeys_server, message, 0);
  free(message);

  // to_send = otrng_prekey_client_request_storage_status(prekey_client);
}

gboolean otrng_prekey_plugin_load(PurplePlugin *handle) {
  if (!otrng_userstate) {
    return FALSE;
  }

  /* Watch to the connect event of every account */
  purple_signal_connect(purple_connections_get_handle(), "signed-on", handle,
                        PURPLE_CALLBACK(account_signed_on_cb), NULL);

  // Do the same on the already connected accounts
  // GList *connections = purple_connections_get_all();
  return TRUE;
}

gboolean otrng_prekey_plugin_unload(PurplePlugin *handle) { return TRUE; }
