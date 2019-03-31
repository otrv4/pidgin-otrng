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

char *otrng_plugin_prekey_domain_for(PurpleAccount *account, const char *who) {
  const char *protocol = purple_account_get_protocol_id(account);

  if (purple_strequal(protocol, "prpl-jabber")) {
    return otrng_plugin_jabber_prekey_domain_for(account, who);
  }

  // TODO: we should do some warning here
  return NULL;
}

void otrng_plugin_prekey_discovery_load() {
  otrng_plugin_prekey_discovery_jabber_load();
}

void otrng_plugin_prekey_discovery_unload() {
  otrng_plugin_prekey_discovery_jabber_unload();
}
