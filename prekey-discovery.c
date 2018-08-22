/*
 * TODO: insert proper copyrights
 */

#include "prekey-discovery.h"
#include "prekey-discovery-jabber.h"

int otrng_plugin_lookup_prekey_servers_for_self(PurpleAccount *account,
                                                PrekeyServerResult result_cb,
                                                void *context) {
  const char *username = purple_account_get_username(account);
  return otrng_plugin_lookup_prekey_servers_for(account, username, result_cb,
                                                context);
}

int otrng_plugin_lookup_prekey_servers_for(PurpleAccount *account,
                                           const char *who,
                                           PrekeyServerResult result_cb,
                                           void *context) {
  if (result_cb == NULL) {
    return 0;
  }

  const char *protocol = purple_account_get_protocol_id(account);

  if (purple_strequal(protocol, "prpl-jabber")) {
    return otrng_plugin_jabber_lookup_prekey_servers_for(account, who,
                                                         result_cb, context);
  }

  return 0;
}

void otrng_plugin_prekey_discovery_load() {
  otrng_plugin_prekey_discovery_jabber_load();
}

void otrng_plugin_prekey_discovery_unload() {
  otrng_plugin_prekey_discovery_jabber_unload();
}
