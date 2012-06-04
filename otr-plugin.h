/*
 *  Off-the-Record Messaging plugin for pidgin
 *  Copyright (C) 2004-2012  Ian Goldberg, Rob Smits,
 *                           Chris Alexander, Willy Lew,
 *                           Lisa Du, Nikita Borisov
 *                           <otr@cypherpunks.ca>
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

#ifndef __OTRG_OTR_PLUGIN_H__
#define __OTRG_OTR_PLUGIN_H__

/* Purple headers */
#include "account.h"
#include "plugin.h"

/* libotr headers */
#include <libotr/context.h>
#include <libotr/userstate.h>
#include <libotr/instag.h>

#define PRIVKEYFNAME "otr.private_key"
#define STOREFNAME "otr.fingerprints"
#define INSTAGFNAME "otr.instance_tags"
#define MAXMSGSIZEFNAME "otr.max_message_size"

extern PurplePlugin *otrg_plugin_handle;

extern OtrlUserState otrg_plugin_userstate;

/* Given a PurpleConversation, return the ConnContext corresponding to the
 * selected instance tag. */
ConnContext* otrg_plugin_conv_to_selected_context(PurpleConversation *conv,
	int force_create);

/* Given a PurpleConversation, return the selected instag. */
otrl_instag_t otrg_plugin_conv_to_selected_instag(PurpleConversation *conv,
	otrl_instag_t default_value);

/* Send an IM from the given account to the given recipient.  Display an
 * error dialog if that account isn't currently logged in. */
void otrg_plugin_inject_message(PurpleAccount *account, const char *recipient,
	const char *message);

/* Generate a private key for the given accountname/protocol */
void otrg_plugin_create_privkey(const char *accountname,
	const char *protocol);

/* Generate a instance tag for the given accountname/protocol */
void otrg_plugin_create_instag(const char *accountname,
	const char *protocol);

/* Start the Socialist Millionaires' Protocol over the current connection,
 * using the given initial secret, and optionally a question to pass to
 * the buddy. */
void otrg_plugin_start_smp(ConnContext *context, const char *question,
	const unsigned char *secret, size_t secretlen);
void otrg_plugin_continue_smp(ConnContext *context,
	const unsigned char *secret, size_t secretlen);

/* Abort the SMP protocol.  Used when malformed or unexpected messages
 * are received. */
void otrg_plugin_abort_smp(ConnContext *context);

/* Send the default OTR Query message to the correspondent of the given
 * context, from the given account.  [account is actually a
 * PurpleAccount*, but it's declared here as void* so this can be passed
 * as a callback.] */
void otrg_plugin_send_default_query(ConnContext *context, void *account);

/* Send the default OTR Query message to the correspondent of the given
 * conversation. */
void otrg_plugin_send_default_query_conv(PurpleConversation *conv);

/* Disconnect a context, sending a notice to the other side, if
 * appropriate. */
void otrg_plugin_disconnect(ConnContext *context);

/* Write the fingerprints to disk. */
void otrg_plugin_write_fingerprints(void);

/* Find the ConnContext appropriate to a given PurpleConversation. */
ConnContext *otrg_plugin_conv_to_context(PurpleConversation *conv,
	otrl_instag_t their_instance, int force_create);

/* Find the PurpleConversation appropriate to the given userinfo.  If
 * one doesn't yet exist, create it if force_create is true. */
PurpleConversation *otrg_plugin_userinfo_to_conv(const char *accountname,
	const char *protocol, const char *username, int force_create);

/* Find the PurpleConversation appropriate to the given ConnContext.  If
 * one doesn't yet exist, create it if force_create is true. */
PurpleConversation *otrg_plugin_context_to_conv(ConnContext *context,
	int force_create);


typedef enum {
    TRUST_NOT_PRIVATE,
    TRUST_UNVERIFIED,
    TRUST_PRIVATE,
    TRUST_FINISHED
} TrustLevel;

/* What level of trust do we have in the privacy of this ConnContext? */
TrustLevel otrg_plugin_context_to_trust(ConnContext *context);

/* Return 1 if the given protocol supports OTR, 0 otherwise. */
int otrg_plugin_proto_supports_otr(const char *proto);

#endif
