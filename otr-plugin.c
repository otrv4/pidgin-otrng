/*
 *  Off-the-Record Messaging plugin for gaim
 *  Copyright (C) 2004-2005  Nikita Borisov and Ian Goldberg
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/* config.h */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* system headers */
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* libgcrypt headers */
#include <gcrypt.h>

/* gaim headers */
#include "gaim.h"
#include "notify.h"
#include "version.h"
#include "util.h"
#include "debug.h"

#ifdef USING_GTK
/* gaim GTK headers */
#include "gtkplugin.h"
#endif

/* libotr headers */
#include <libotr/privkey.h>
#include <libotr/proto.h>
#include <libotr/message.h>
#include <libotr/userstate.h>

/* gaim-otr headers */
#include "ui.h"
#include "dialogs.h"
#include "otr-plugin.h"

#ifdef USING_GTK
/* gaim-otr GTK headers */
#include "gtk-ui.h"
#include "gtk-dialog.h"
#endif

GaimPlugin *otrg_plugin_handle;

/* We'll only use the one OtrlUserState. */
OtrlUserState otrg_plugin_userstate = NULL;

/* Send an IM from the given account to the given recipient.  Display an
 * error dialog if that account isn't currently logged in. */
void otrg_plugin_inject_message(GaimAccount *account, const char *recipient,
	const char *message)
{
    GaimConnection *connection;

    connection = gaim_account_get_connection(account);
    if (!connection) {
	const char *protocol = gaim_account_get_protocol_id(account);
	const char *accountname = gaim_account_get_username(account);
	GaimPlugin *p = gaim_find_prpl(protocol);
	char *msg = g_strdup_printf("You are not currently connected to "
		"account %s (%s).", accountname,
		(p && p->info->name) ? p->info->name : "Unknown");
	otrg_dialog_notify_error(accountname, protocol, recipient,
		"Not connected", msg, NULL);
	g_free(msg);
	return;
    }
    serv_send_im(connection, recipient, message, 0);
}

static OtrlPolicy policy_cb(void *opdata, ConnContext *context)
{
    GaimAccount *account;
    OtrlPolicy policy = OTRL_POLICY_DEFAULT;

    if (!context) return policy;

    account = gaim_accounts_find(context->accountname, context->protocol);
    if (!account) return policy;

    return otrg_ui_find_policy(account, context->username);
}

static const char *protocol_name_cb(void *opdata, const char *protocol)
{
    GaimPlugin *p = gaim_find_prpl(protocol);
    if (!p) return NULL;
    return p->info->name;
}

static void protocol_name_free_cb(void *opdata, const char *protocol_name)
{
    /* Do nothing, since we didn't actually allocate any memory in
     * protocol_name_cb. */
}

/* Generate a private key for the given accountname/protocol */
void otrg_plugin_create_privkey(const char *accountname,
	const char *protocol)
{
    OtrgDialogWaitHandle waithandle;

    gchar *privkeyfile = g_build_filename(gaim_user_dir(), PRIVKEYFNAME, NULL);
    if (!privkeyfile) {
	fprintf(stderr, "Out of memory building filenames!\n");
	return;
    }

    waithandle = otrg_dialog_private_key_wait_start(accountname, protocol);

    /* Generate the key */
    otrl_privkey_generate(otrg_plugin_userstate, privkeyfile,
	    accountname, protocol);
    g_free(privkeyfile);
    otrg_ui_update_fingerprint();

    /* Mark the dialog as done. */
    otrg_dialog_private_key_wait_done(waithandle);
}

static void create_privkey_cb(void *opdata, const char *accountname,
	const char *protocol)
{
    otrg_plugin_create_privkey(accountname, protocol);
}

static int is_logged_in_cb(void *opdata, const char *accountname,
	const char *protocol, const char *recipient)
{
    GaimAccount *account;
    GaimBuddy *buddy;

    account = gaim_accounts_find(accountname, protocol);
    if (!account) return -1;

    buddy = gaim_find_buddy(account, recipient);
    if (!buddy) return -1;

    return (buddy->present == GAIM_BUDDY_ONLINE);
}

static void inject_message_cb(void *opdata, const char *accountname,
	const char *protocol, const char *recipient, const char *message)
{
    GaimAccount *account = gaim_accounts_find(accountname, protocol);
    if (!account) {
	GaimPlugin *p = gaim_find_prpl(protocol);
	char *msg = g_strdup_printf("Unknown account %s (%s).", accountname,
		(p && p->info->name) ? p->info->name : "Unknown");
	otrg_dialog_notify_error(accountname, protocol, recipient,
		"Unknown account", msg, NULL);
	g_free(msg);
	return;
    }
    otrg_plugin_inject_message(account, recipient, message);
}

static void notify_cb(void *opdata, OtrlNotifyLevel level,
	const char *accountname, const char *protocol, const char *username,
	const char *title, const char *primary, const char *secondary)
{
    GaimNotifyMsgType gaimlevel = GAIM_NOTIFY_MSG_ERROR;

    switch (level) {
	case OTRL_NOTIFY_ERROR:
	    gaimlevel = GAIM_NOTIFY_MSG_ERROR;
	    break;
	case OTRL_NOTIFY_WARNING:
	    gaimlevel = GAIM_NOTIFY_MSG_WARNING;
	    break;
	case OTRL_NOTIFY_INFO:
	    gaimlevel = GAIM_NOTIFY_MSG_INFO;
	    break;
    }

    otrg_dialog_notify_message(gaimlevel, accountname, protocol,
	    username, title, primary, secondary);
}

static int display_otr_message_cb(void *opdata, const char *accountname,
	const char *protocol, const char *username, const char *msg)
{
    return otrg_dialog_display_otr_message(accountname, protocol,
	    username, msg);
}

static void update_context_list_cb(void *opdata)
{
    otrg_ui_update_keylist();
}

static void confirm_fingerprint_cb(OtrlUserState us, void *opdata,
	const char *accountname, const char *protocol, const char *username,
	OTRKeyExchangeMsg kem)
{
    otrg_dialog_unknown_fingerprint(us, accountname, protocol, username, kem);
}

static void write_fingerprints_cb(void *opdata)
{
    otrg_plugin_write_fingerprints();
}

static void gone_secure_cb(void *opdata, ConnContext *context)
{
    otrg_dialog_connected(context);
}

static void gone_insecure_cb(void *opdata, ConnContext *context)
{
    otrg_dialog_disconnected(context);
}

static void still_secure_cb(void *opdata, ConnContext *context, int is_reply)
{
    if (is_reply == 0) {
	otrg_dialog_stillconnected(context);
    }
}

static void log_message_cb(void *opdata, const char *message)
{
    gaim_debug_info("otr", message);
}

static OtrlMessageAppOps ui_ops = {
    policy_cb,
    create_privkey_cb,
    is_logged_in_cb,
    inject_message_cb,
    notify_cb,
    display_otr_message_cb,
    update_context_list_cb,
    protocol_name_cb,
    protocol_name_free_cb,
    confirm_fingerprint_cb,
    write_fingerprints_cb,
    gone_secure_cb,
    gone_insecure_cb,
    still_secure_cb,
    log_message_cb
};

static void process_sending_im(GaimAccount *account, char *who, char **message,
	void *m)
{
    char *newmessage = NULL;
    const char *accountname = gaim_account_get_username(account);
    const char *protocol = gaim_account_get_protocol_id(account);
    char *username;
    gcry_error_t err;

    if (!who || !message || !*message)
	return;

    username = strdup(gaim_normalize(account, who));

    err = otrl_message_sending(otrg_plugin_userstate, &ui_ops, NULL,
	    accountname, protocol, username, *message, NULL, &newmessage,
	    NULL, NULL);

    if (err && newmessage == NULL) {
	/* Be *sure* not to send out plaintext */
	char *ourm = strdup("");
	free(*message);
	*message = ourm;
    } else if (newmessage) {
	char *ourm = malloc(strlen(newmessage) + 1);
	if (ourm) {
	    strcpy(ourm, newmessage);
	}
	otrl_message_free(newmessage);
	free(*message);
	*message = ourm;
    }
    free(username);
}

/* Send the default OTR Query message to the correspondent of the given
 * context, from the given account.  [account is actually a
 * GaimAccount*, but it's declared here as void* so this can be passed
 * as a callback.] */
void otrg_plugin_send_default_query(ConnContext *context, void *account)
{
    char *msg = otrl_proto_default_query_msg(context->accountname);
    otrg_plugin_inject_message((GaimAccount *)account, context->username,
	    msg ? msg : "?OTR?");
    free(msg);
}

/* Send the default OTR Query message to the correspondent of the given
 * conversation. */
void otrg_plugin_send_default_query_conv(GaimConversation *conv)
{
    GaimAccount *account;
    const char *username, *accountname;
    char *msg;
    
    account = gaim_conversation_get_account(conv);
    accountname = gaim_account_get_username(account);
    username = gaim_conversation_get_name(conv);
    
    msg = otrl_proto_default_query_msg(accountname);
    otrg_plugin_inject_message(account, username, msg ? msg : "?OTR?");
    free(msg);
}

static gboolean process_receiving_im(GaimAccount *account, char **who, 
        char **message, int *flags, void *m)
{
    char *newmessage = NULL;
    OtrlTLV *tlvs = NULL;
    OtrlTLV *tlv = NULL;
    char *username;
    gboolean res;
    const char *accountname;
    const char *protocol;

    if (!who || !*who || !message || !*message)
        return 0;

    username = strdup(gaim_normalize(account, *who));
    accountname = gaim_account_get_username(account);
    protocol = gaim_account_get_protocol_id(account);

    res = otrl_message_receiving(otrg_plugin_userstate, &ui_ops, NULL,
	    accountname, protocol, username, *message,
	    &newmessage, &tlvs, NULL, NULL);

    if (newmessage) {
	char *ourm = malloc(strlen(newmessage) + 1);
	if (ourm) {
	    strcpy(ourm, newmessage);
	}
	otrl_message_free(newmessage);
	free(*message);
	*message = ourm;
    }

    tlv = otrl_tlv_find(tlvs, OTRL_TLV_DISCONNECTED);
    if (tlv) {
	/* Notify the user that the other side disconnected. */

	char *msg = g_strdup_printf("OTR: %s has closed his private "
		"connection to you; you should do the same.", username);

	if (msg) {
	    otrg_dialog_display_otr_message(accountname, protocol,
		    username, msg);
	    g_free(msg);
	}
    }
    
    otrl_tlv_free(tlvs);

    free(username);

    /* If we're supposed to ignore this incoming message (because it's a
     * protocol message), set it to NULL, so that other plugins that
     * catch receiving-im-msg don't return 0, and cause it to be
     * displayed anyway. */
    if (res) {
	free(*message);
	*message = NULL;
    }
    return res;
}

static void process_conv_create(GaimConversation *conv, void *data)
{
    if (conv) otrg_dialog_new_conv(conv);
}

static void process_connection_change(GaimConnection *conn, void *data)
{
    /* If we log in or out of a connection, make sure all of the OTR
     * buttons are in the appropriate sensitive/insensitive state. */
    otrg_dialog_resensitize_all();
}

static void process_button_type_change(const char *name, GaimPrefType type,
	gpointer value, gpointer data)
{
    /* If the user changes the style of the buttons at the bottom of the
     * conversation window, gaim annoyingly removes all the buttons from
     * the bbox, and reinserts its own.  So we need to reinsert our
     * buttons as well. */
    otrg_dialog_resensitize_all();
}

static void otr_options_cb(GaimBlistNode *node, gpointer user_data)
{
    /* We've already checked GAIM_BLIST_NODE_IS_BUDDY(node) */
    GaimBuddy *buddy = (GaimBuddy *)node;

    /* Modify the settings for this buddy */
    otrg_ui_config_buddy(buddy);
}

static void supply_extended_menu(GaimBlistNode *node, GList **menu)
{
    GaimBlistNodeAction *act;
    GaimBuddy *buddy;
    GaimAccount *acct;
    const char *proto;

    if (!GAIM_BLIST_NODE_IS_BUDDY(node)) return;

    /* Extract the account, and then the protocol, for this buddy */
    buddy = (GaimBuddy *)node;
    acct = buddy->account;
    if (acct == NULL) return;
    proto = gaim_account_get_protocol_id(acct);
    if (!otrg_plugin_proto_supports_otr(proto)) return;

    act = gaim_blist_node_action_new("OTR Settings", otr_options_cb, NULL);
    *menu = g_list_append(*menu, act);
}

/* Disconnect a context, sending a notice to the other side, if
 * appropriate. */
void otrg_plugin_disconnect(ConnContext *context)
{
    otrl_message_disconnect(otrg_plugin_userstate, &ui_ops, NULL,
	    context->accountname, context->protocol, context->username);
}

/* Write the fingerprints to disk. */
void otrg_plugin_write_fingerprints(void)
{
    gchar *storefile = g_build_filename(gaim_user_dir(), STOREFNAME, NULL);
    otrl_privkey_write_fingerprints(otrg_plugin_userstate, storefile);
    g_free(storefile);
}

/* Find the ConnContext appropriate to a given GaimConversation. */
ConnContext *otrg_plugin_conv_to_context(GaimConversation *conv)
{
    GaimAccount *account;
    char *username;
    const char *accountname, *proto;
    ConnContext *context;

    account = gaim_conversation_get_account(conv);
    accountname = gaim_account_get_username(account);
    proto = gaim_account_get_protocol_id(account);
    username = g_strdup(
	    gaim_normalize(account, gaim_conversation_get_name(conv)));

    context = otrl_context_find(otrg_plugin_userstate, username, accountname,
	    proto, 0, NULL, NULL, NULL);
    g_free(username);

    return context;
}

/* Find the GaimConversation appropriate to the given ConnContext.  If
 * one doesn't yet exist, create it if force_create is true. */
GaimConversation *otrg_plugin_context_to_conv(ConnContext *context,
	int force_create)
{
    GaimAccount *account;
    GaimConversation *conv;

    account = gaim_accounts_find(context->accountname, context->protocol);
    if (account == NULL) return NULL;

    conv = gaim_find_conversation_with_account(context->username, account);
    if (conv == NULL && force_create) {
	conv = gaim_conversation_new(GAIM_CONV_IM, account, context->username);
    }

    return conv;
}

/* What level of trust do we have in the privacy of this ConnContext? */
TrustLevel otrg_plugin_context_to_trust(ConnContext *context)
{
    TrustLevel level = TRUST_NOT_PRIVATE;

    if (context && context->state == CONN_CONNECTED) {
	if (context->active_fingerprint->trust &&
		context->active_fingerprint->trust[0] != '\0') {
	    level = TRUST_PRIVATE;
	} else {
	    level = TRUST_UNVERIFIED;
	}
    }

    return level;
}

static guint button_type_cbid;

static gboolean otr_plugin_load(GaimPlugin *handle)
{
    gchar *privkeyfile = g_build_filename(gaim_user_dir(), PRIVKEYFNAME, NULL);
    gchar *storefile = g_build_filename(gaim_user_dir(), STOREFNAME, NULL);
    void *conv_handle = gaim_conversations_get_handle();
    void *conn_handle = gaim_connections_get_handle();
    void *blist_handle = gaim_blist_get_handle();

    if (!privkeyfile || !storefile) {
	g_free(privkeyfile);
	g_free(storefile);
	return 0;
    }

    otrg_plugin_handle = handle;

    /* Make our OtrlUserState; we'll only use the one. */
    otrg_plugin_userstate = otrl_userstate_create();

    otrl_privkey_read(otrg_plugin_userstate, privkeyfile);
    g_free(privkeyfile);
    otrl_privkey_read_fingerprints(otrg_plugin_userstate, storefile,
	    NULL, NULL);
    g_free(storefile);

    otrg_ui_update_fingerprint();

    gaim_signal_connect(conv_handle, "sending-im-msg", otrg_plugin_handle,
            GAIM_CALLBACK(process_sending_im), NULL);
    gaim_signal_connect(conv_handle, "receiving-im-msg", otrg_plugin_handle,
            GAIM_CALLBACK(process_receiving_im), NULL);
    gaim_signal_connect(conv_handle, "conversation-created",
	    otrg_plugin_handle, GAIM_CALLBACK(process_conv_create), NULL);
    gaim_signal_connect(conn_handle, "signed-on", otrg_plugin_handle,
	    GAIM_CALLBACK(process_connection_change), NULL);
    gaim_signal_connect(conn_handle, "signed-off", otrg_plugin_handle,
	    GAIM_CALLBACK(process_connection_change), NULL);
    gaim_signal_connect(blist_handle, "blist-node-extended-menu",
	    otrg_plugin_handle, GAIM_CALLBACK(supply_extended_menu), NULL);
    button_type_cbid = gaim_prefs_connect_callback(
	    "/gaim/gtk/conversations/button_type",
	    process_button_type_change, NULL);

    gaim_conversation_foreach(otrg_dialog_new_conv);

    return 1;
}

static gboolean otr_plugin_unload(GaimPlugin *handle)
{
    void *conv_handle = gaim_conversations_get_handle();
    void *conn_handle = gaim_connections_get_handle();
    void *blist_handle = gaim_blist_get_handle();

    /* Clean up all of our state. */
    otrl_userstate_free(otrg_plugin_userstate);
    otrg_plugin_userstate = NULL;

    gaim_signal_disconnect(conv_handle, "sending-im-msg", otrg_plugin_handle,
            GAIM_CALLBACK(process_sending_im));
    gaim_signal_disconnect(conv_handle, "receiving-im-msg", otrg_plugin_handle,
            GAIM_CALLBACK(process_receiving_im));
    gaim_signal_disconnect(conv_handle, "conversation-created",
	    otrg_plugin_handle, GAIM_CALLBACK(process_conv_create));
    gaim_signal_disconnect(conn_handle, "signed-on", otrg_plugin_handle,
	    GAIM_CALLBACK(process_connection_change));
    gaim_signal_disconnect(conn_handle, "signed-off", otrg_plugin_handle,
	    GAIM_CALLBACK(process_connection_change));
    gaim_signal_disconnect(blist_handle, "blist-node-extended-menu",
	    otrg_plugin_handle, GAIM_CALLBACK(supply_extended_menu));
    gaim_prefs_disconnect_callback(button_type_cbid);

    gaim_conversation_foreach(otrg_dialog_remove_conv);

    return 1;
}

/* Return 1 if the given protocol supports OTR, 0 otherwise. */
int otrg_plugin_proto_supports_otr(const char *proto)
{
    /* IRC is the only protocol we know of that OTR doesn't work on (its
     * maximum message size is too small to fit a Key Exchange Message). */
    if (proto && !strcmp(proto, "prpl-irc")) {
	return 0;
    }
    return 1;
}

#ifdef USING_GTK

static GaimGtkPluginUiInfo ui_info =
{
	otrg_gtk_ui_make_widget
};

#define UI_INFO &ui_info
#define PLUGIN_TYPE GAIM_GTK_PLUGIN_TYPE

#else

#define UI_INFO NULL
#define PLUGIN_TYPE ""

#endif

static GaimPluginInfo info =
{
	GAIM_PLUGIN_MAGIC,

	/* We stick with the functions in the gaim 1.0.x API for
	 * compatibility. */
	1,                                                /* major version  */
	0,                                                /* minor version  */

	GAIM_PLUGIN_STANDARD,                             /* type           */
	PLUGIN_TYPE,                                      /* ui_requirement */
	0,                                                /* flags          */
	NULL,                                             /* dependencies   */
	GAIM_PRIORITY_DEFAULT,                            /* priority       */
	"otr",                                            /* id             */
	"Off-the-Record Messaging",                       /* name           */
	GAIM_OTR_VERSION,                                 /* version        */
	                                                  /* summary        */
	"Provides private and secure conversations",
	                                                  /* description    */
	"Preserves the privacy of IM communications by providing "
	    "encryption, authentication, deniability, and perfect "
	    "forward secrecy.",
	                                                  /* author         */
	"Nikita Borisov and Ian Goldberg\n\t\t\t<otr@cypherpunks.ca>",
	"http://www.cypherpunks.ca/otr/",                 /* homepage       */

	otr_plugin_load,                                 /* load           */
	otr_plugin_unload,                               /* unload         */
	NULL,                                             /* destroy        */

	UI_INFO,                                          /* ui_info        */
	NULL,                                             /* extra_info     */
	NULL,                                             /* prefs_info     */
	NULL                                              /* actions        */
};

static void
__init_plugin(GaimPlugin *plugin)
{
    /* Set up the UI ops */
#ifdef USING_GTK
    otrg_ui_set_ui_ops(otrg_gtk_ui_get_ui_ops());
    otrg_dialog_set_ui_ops(otrg_gtk_dialog_get_ui_ops());
#endif

    /* Initialize the OTR library */
    OTRL_INIT;
}

GAIM_INIT_PLUGIN(otr, __init_plugin, info)
