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

#include <libotr4/messaging.h>

/* libotr4 headers */
#include "otr4-client.h"

#define PRIVKEYFNAMEv4 "otr4.private_key"
#define STOREFNAMEv4 "otr4.fingerprints"

#define PRIVKEYFNAME "otr.private_key"
#define STOREFNAME "otr.fingerprints"
#define INSTAGFNAME "otr.instance_tags"
#define MAXMSGSIZEFNAME "otr.max_message_size"

extern PurplePlugin *otrg_plugin_handle;

extern otr4_userstate_t *otr4_userstate;
extern OtrlUserState otrg_plugin_userstate;

otr4_client_t*
otr4_client(const char *accountname, const char *protocol);

otr4_client_adapter_t*
purple_account_to_otr4_client(PurpleAccount *account);

otr4_conversation_t*
purple_conversation_to_otr4_conversation(const PurpleConversation *conv);

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

//TODO: REPLACE by using opdata to get this information
typedef struct {
    char *account;
    char *protocol;
    char *peer;
    uint16_t their_instance_tag;
    uint16_t our_instance_tag;
} otrg_plugin_conversation;

otrg_plugin_conversation*
purple_conversation_to_plugin_conversation(const PurpleConversation *conv);

otr4_client_adapter_t *
otrg_plugin_conversation_to_client(const otrg_plugin_conversation *conv);

otrg_plugin_conversation*
otrg_plugin_conversation_copy(const otrg_plugin_conversation*);

void
otrg_plugin_conversation_free(otrg_plugin_conversation*);

/* Start the Socialist Millionaires' Protocol over the current connection,
 * using the given initial secret, and optionally a question to pass to
 * the buddy. */
void otrg_plugin_start_smp(otrg_plugin_conversation *plugin_conv,
    const char *question, const unsigned char *secret, size_t secretlen);

void otrg_plugin_continue_smp(otrg_plugin_conversation *conv,
	const unsigned char *secret, size_t secretlen);

/* Abort the SMP protocol.  Used when malformed or unexpected messages
 * are received. */
void otrg_plugin_abort_smp(const otrg_plugin_conversation *conv);

void otrg_plugin_send_default_query(otrg_plugin_conversation *conv);

/* Send the default OTR Query message to the correspondent of the given
 * conversation. */
void otrg_plugin_send_default_query_conv(PurpleConversation *conv);

/* Disconnect a context, sending a notice to the other side, if
 * appropriate. */
void otrg_plugin_disconnect(otrg_plugin_conversation *conv);

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

TrustLevel otrg_plugin_conversation_to_trust(const otrg_plugin_conversation *conv);

/* What level of trust do we have in the privacy of this ConnContext? */
TrustLevel otrg_plugin_context_to_trust(ConnContext *context);

/* Return 1 if the given protocol supports OTR, 0 otherwise. */
int otrg_plugin_proto_supports_otr(const char *proto);

int
otrg_plugin_conversation_to_protocol_version(const otrg_plugin_conversation *conv);

static inline PurpleConversation *otrg_plugin_conversation_to_purple_conv(const otrg_plugin_conversation *conv, int force) {
  return otrg_plugin_userinfo_to_conv(conv->account, conv->protocol,
      conv->peer, force);
}

typedef struct {
    char *protocol;
    char *account;
    char *username;
    char fp[OTR4_FPRINT_HUMAN_LEN];
    int trusted; //0 - no, 1 - yes
} otrg_plugin_fingerprint;

//otrg_plugin_fingerprint*
//otrg_plugin_fingerprint_get(const char fp[OTR4_FPRINT_HUMAN_LEN]);

otr4_conversation_t*
otrg_plugin_fingerprint_to_otr_conversation(otrg_plugin_fingerprint *f);

GList *
otrg_plugin_fingerprint_get_all(void);

otrg_plugin_fingerprint*
otrg_plugin_fingerprint_get_active(const char *peer);

void
otrg_plugin_fingerprint_forget(const char fp[OTR4_FPRINT_HUMAN_LEN]);

#endif
