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

#ifndef __OTRG_PIDGIN_HELPERS_H__
#define __OTRG_PIDGIN_HELPERS_H__

#include <stdio.h>

/* Purple headers */
#include <account.h>

#include <libotr-ng/messaging.h>

#include "plugin-conversation.h"

otrng_client_id_s protocol_and_account_to_client_id(const char *protocol,
                                                    const char *account);

otrng_client_id_s purple_account_to_client_id(const PurpleAccount *account);

PurpleAccount *protocol_and_account_to_purple_account(const char *protocol,
                                                      const char *accountname);

PurpleAccount *client_id_to_purple_account(const otrng_client_id_s client_id);

otrng_client_s *get_otrng_client(const char *protocol, const char *accountname);

otrng_client_s *purple_account_to_otrng_client(const PurpleAccount *account);

otrng_conversation_s *
purple_conversation_to_otrng_conversation(const PurpleConversation *conv);

otrng_client_id_s protocol_and_account_to_purple_conversation(FILE *privf);

otrng_plugin_conversation *
client_conversation_to_plugin_conversation(const otrng_s *conv);

#endif
