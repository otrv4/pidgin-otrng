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

#include <account.h>
#include <assert.h>
#include <glib.h>
#include <gtkconv.h>

#include "fingerprint.h"
#include "pidgin-helpers.h"

#include <libotr-ng/client.h>
#include <libotr-ng/messaging.h>

extern otrng_global_state_s *otrng_state;

otrng_client_id_s protocol_and_account_to_client_id(const char *protocol,
                                                    const char *account) {
  assert(protocol != NULL);
  assert(account != NULL);

  otrng_client_id_s result = {
      .protocol = protocol,
      .account = account,
  };
  return result;
}

otrng_client_id_s purple_account_to_client_id(const PurpleAccount *account) {
  const char *protocol, *accountname;

  assert(account != NULL);

  protocol = purple_account_get_protocol_id(account);
  accountname =
      g_strdup(purple_normalize(account, purple_account_get_username(account)));
  return protocol_and_account_to_client_id(protocol, accountname);
}

PurpleAccount *protocol_and_account_to_purple_account(const char *protocol,
                                                      const char *accountname) {
  PurpleAccount *result;

  assert(protocol != NULL);
  assert(accountname != NULL);

  result = purple_accounts_find(accountname, protocol);

  assert(result != NULL);

  return result;
}

PurpleAccount *client_id_to_purple_account(const otrng_client_id_s client_id) {
  return protocol_and_account_to_purple_account(client_id.protocol,
                                                client_id.account);
}

otrng_client_s *get_otrng_client(const char *protocol,
                                 const char *accountname) {
  return get_otrng_client_from_id(
      protocol_and_account_to_client_id(protocol, accountname));
}

otrng_client_s *get_otrng_client_from_id(const otrng_client_id_s client_id) {
  otrng_client_s *result = otrng_client_get(otrng_state, client_id);
  assert(result != NULL);
  return result;
}

// TODO: REMOVE
otrng_client_s *purple_account_to_otrng_client(const PurpleAccount *account) {
  otrng_client_s *client =
      otrng_client_get(otrng_state, purple_account_to_client_id(account));

  assert(client != NULL);

  /* You can set some configurations here */
  // otrng_client_set_padding(256, client);

  return client;
}

otrng_conversation_s *
purple_conversation_to_otrng_conversation(const PurpleConversation *conv) {
  PurpleAccount *account = NULL;
  char *recipient = NULL;

  assert(conv != NULL);

  account = purple_conversation_get_account(conv);

  assert(account != NULL);

  recipient =
      g_strdup(purple_normalize(account, purple_conversation_get_name(conv)));

  otrng_client_s *client =
      otrng_client_get(otrng_state, purple_account_to_client_id(account));

  otrng_conversation_s *result =
      otrng_client_get_conversation(1, recipient, client);
  free(recipient);

  assert(result != NULL);

  return result;
}

otrng_client_id_s protocol_and_account_to_purple_conversation(FILE *privf) {
  char *line = NULL;
  size_t cap = 0;
  int len = 0;

  otrng_client_id_s null_result = {
      .protocol = NULL,
      .account = NULL,
  };

  if (!privf) {
    return null_result;
  }

  while ((len = getline(&line, &cap, privf)) != -1) {
    char *delim = strchr(line, ':');

    if (!delim) {
      return null_result;
    }
    *delim = 0;
    line[len - 1] = 0; /* \n */

    return protocol_and_account_to_client_id(line, delim + 1);
  }

  return null_result;
}

otrng_plugin_conversation *
client_conversation_to_plugin_conversation(const otrng_s *conv) {
  // TODO: Instance tag?
  return otrng_plugin_conversation_new(conv);
}

/* Find the PurpleConversation appropriate to the given userinfo.  If
 * one doesn't yet exist, create it if force_create is true. */
PurpleConversation *otrng_plugin_userinfo_to_conv(const char *accountname,
                                                  const char *protocol,
                                                  const char *username,
                                                  int force_create) {
  PurpleAccount *account;
  PurpleConversation *conv;
  const char *hide_im_conversations;

  account = purple_accounts_find(accountname, protocol);
  if (account == NULL) {
    return NULL;
  }

  conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, username,
                                               account);
  if (conv == NULL && force_create) {
    conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, account, username);
    hide_im_conversations = purple_prefs_get_string("/pidgin/conversations/im/hide_new");

    if( strcmp(hide_im_conversations,"always")==0 ){
    	  PidginConversation *gtkconv = PIDGIN_CONVERSATION(conv);
    	  PidginWindow *win = pidgin_conv_get_window(gtkconv);
    	  pidgin_conv_window_hide( win );
    }

  }

  return conv;
}
