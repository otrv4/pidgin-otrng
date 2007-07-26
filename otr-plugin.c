/*
 *  Off-the-Record Messaging plugin for pidgin
 *  Copyright (C) 2004-2007  Ian Goldberg, Chris Alexander, Nikita Borisov
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

/* purple headers */
#include "pidgin.h"
#include "notify.h"
#include "version.h"
#include "util.h"
#include "debug.h"
#include "core.h"

#ifdef USING_GTK
/* purple GTK headers */
#include "gtkplugin.h"
#endif

#ifdef ENABLE_NLS

#ifdef WIN32
/* On Win32, include win32dep.h from pidgin for correct definition
 * of LOCALEDIR */
#include "win32dep.h"
#endif /* WIN32 */

/* internationalisation header */
#include <glib/gi18n-lib.h>

#endif /* ENABLE_NLS */

/* libotr headers */
#include <libotr/privkey.h>
#include <libotr/proto.h>
#include <libotr/tlv.h>
#include <libotr/message.h>
#include <libotr/userstate.h>

/* purple-otr headers */
#include "ui.h"
#include "dialogs.h"
#include "otr-plugin.h"

#ifdef USING_GTK
/* purple-otr GTK headers */
#include <glib.h>
#include "gtk-ui.h"
#include "gtk-dialog.h"
#endif

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

PurplePlugin *otrg_plugin_handle;

/* We'll only use the one OtrlUserState. */
OtrlUserState otrg_plugin_userstate = NULL;

/* GLib HashTable for storing the maximum message size for various
 * protocols. */
GHashTable* mms_table;

/* Send an IM from the given account to the given recipient.  Display an
 * error dialog if that account isn't currently logged in. */
void otrg_plugin_inject_message(PurpleAccount *account, const char *recipient,
	const char *message)
{
    PurpleConnection *connection;

    connection = purple_account_get_connection(account);
    if (!connection) {
	const char *protocol = purple_account_get_protocol_id(account);
	const char *accountname = purple_account_get_username(account);
	PurplePlugin *p = purple_find_prpl(protocol);
	char *msg = g_strdup_printf(_("You are not currently connected to "
		"account %s (%s)."), accountname,
		(p && p->info->name) ? p->info->name : _("Unknown"));
	otrg_dialog_notify_error(accountname, protocol, recipient,
		_("Not connected"), msg, NULL);
	g_free(msg);
	return;
    }
    serv_send_im(connection, recipient, message, 0);
}

static OtrlPolicy policy_cb(void *opdata, ConnContext *context)
{
    PurpleAccount *account;
    OtrlPolicy policy = OTRL_POLICY_DEFAULT;
    OtrgUiPrefs prefs;

    if (!context) return policy;

    account = purple_accounts_find(context->accountname, context->protocol);
    if (!account) return policy;

    otrg_ui_get_prefs(&prefs, account, context->username);
    return prefs.policy;
}

static const char *protocol_name_cb(void *opdata, const char *protocol)
{
    PurplePlugin *p = purple_find_prpl(protocol);
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
    FILE *privf;

    gchar *privkeyfile = g_build_filename(purple_user_dir(), PRIVKEYFNAME, NULL);
    if (!privkeyfile) {
	fprintf(stderr, _("Out of memory building filenames!\n"));
	return;
    }
    privf = g_fopen(privkeyfile, "w+b");
    g_free(privkeyfile);
    if (!privf) {
	fprintf(stderr, _("Could not write private key file\n"));
	return;
    }

    waithandle = otrg_dialog_private_key_wait_start(accountname, protocol);

    /* Generate the key */
    otrl_privkey_generate_FILEp(otrg_plugin_userstate, privf,
	    accountname, protocol);
    fclose(privf);
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
    PurpleAccount *account;
    PurpleBuddy *buddy;

    account = purple_accounts_find(accountname, protocol);
    if (!account) return -1;

    buddy = purple_find_buddy(account, recipient);
    if (!buddy) return -1;

    return (PURPLE_BUDDY_IS_ONLINE(buddy));
}

static void inject_message_cb(void *opdata, const char *accountname,
	const char *protocol, const char *recipient, const char *message)
{
    PurpleAccount *account = purple_accounts_find(accountname, protocol);
    if (!account) {
	PurplePlugin *p = purple_find_prpl(protocol);
	char *msg = g_strdup_printf(_("Unknown account %s (%s)."),
		accountname,
		(p && p->info->name) ? p->info->name : _("Unknown"));
	otrg_dialog_notify_error(accountname, protocol, recipient,
		_("Unknown account"), msg, NULL);
	g_free(msg);
	return;
    }
    otrg_plugin_inject_message(account, recipient, message);
}

static void notify_cb(void *opdata, OtrlNotifyLevel level,
	const char *accountname, const char *protocol, const char *username,
	const char *title, const char *primary, const char *secondary)
{
    PurpleNotifyMsgType purplelevel = PURPLE_NOTIFY_MSG_ERROR;

    switch (level) {
	case OTRL_NOTIFY_ERROR:
	    purplelevel = PURPLE_NOTIFY_MSG_ERROR;
	    break;
	case OTRL_NOTIFY_WARNING:
	    purplelevel = PURPLE_NOTIFY_MSG_WARNING;
	    break;
	case OTRL_NOTIFY_INFO:
	    purplelevel = PURPLE_NOTIFY_MSG_INFO;
	    break;
    }

    otrg_dialog_notify_message(purplelevel, accountname, protocol,
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

static void confirm_fingerprint_cb(void *opdata, OtrlUserState us,
	const char *accountname, const char *protocol, const char *username,
	unsigned char fingerprint[20])
{
    otrg_dialog_unknown_fingerprint(us, accountname, protocol, username,
	    fingerprint);
}

static void write_fingerprints_cb(void *opdata)
{
    otrg_plugin_write_fingerprints();
    otrg_ui_update_keylist();
    otrg_dialog_resensitize_all();
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
    purple_debug_info("otr", message);
}

static int max_message_size_cb(void *opdata, ConnContext *context)
{
    void* lookup_result = g_hash_table_lookup(mms_table, context->protocol);
    if (!lookup_result)
        return 0;
    else
        return *((int*)lookup_result);
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
    log_message_cb,
    max_message_size_cb,
    NULL,                   /* account_name */
    NULL                    /* account_name_free */
};

static void process_sending_im(PurpleAccount *account, char *who,
	char **message, void *m)
{
    char *newmessage = NULL;
    const char *accountname = purple_account_get_username(account);
    const char *protocol = purple_account_get_protocol_id(account);
    char *username;
    gcry_error_t err;

    if (!who || !message || !*message)
	return;

    username = strdup(purple_normalize(account, who));

    err = otrl_message_sending(otrg_plugin_userstate, &ui_ops, NULL,
	    accountname, protocol, username, *message, NULL, &newmessage,
	    NULL, NULL);

    if (err && newmessage == NULL) {
	/* Be *sure* not to send out plaintext */
	char *ourm = strdup("");
	free(*message);
	*message = ourm;
    } else if (newmessage) {
	/* Fragment the message if necessary, and send all but the last
	 * fragment over the network.  Pidgin will send the last
	 * fragment for us. */
	ConnContext *context = otrl_context_find(otrg_plugin_userstate,
		username, accountname, protocol, 0, NULL, NULL, NULL);
	free(*message);
	*message = NULL;
	err = otrl_message_fragment_and_send(&ui_ops, NULL, context,
		newmessage, OTRL_FRAGMENT_SEND_ALL_BUT_LAST, message);
	otrl_message_free(newmessage);
    }
    free(username);
}

/* Abort the SMP protocol.  Used when malformed or unexpected messages
 * are received. */
void otrg_plugin_abort_smp(ConnContext *context)
{
    otrl_message_abort_smp(otrg_plugin_userstate, &ui_ops, NULL, context);
}

/* Start the Socialist Millionaires' Protocol over the current connection,
 * using the given initial secret. */
void otrg_plugin_start_smp(ConnContext *context,
	const unsigned char *secret, size_t secretlen)
{
    otrl_message_initiate_smp(otrg_plugin_userstate, &ui_ops, NULL,
	    context, secret, secretlen);
}

/* Continue the Socialist Millionaires' Protocol over the current connection,
 * using the given initial secret (ie finish step 2). */
void otrg_plugin_continue_smp(ConnContext *context,
	const unsigned char *secret, size_t secretlen)
{
    otrl_message_respond_smp(otrg_plugin_userstate, &ui_ops, NULL,
	    context, secret, secretlen);
}

/* Send the default OTR Query message to the correspondent of the given
 * context, from the given account.  [account is actually a
 * PurpleAccount*, but it's declared here as void* so this can be passed
 * as a callback.] */
void otrg_plugin_send_default_query(ConnContext *context, void *vaccount)
{
    PurpleAccount *account = vaccount;
    char *msg;
    OtrgUiPrefs prefs;

    otrg_ui_get_prefs(&prefs, account, context->username);
    msg = otrl_proto_default_query_msg(context->accountname,
	    prefs.policy);
    otrg_plugin_inject_message(account, context->username,
	    msg ? msg : "?OTRv2?");
    free(msg);
}

/* Send the default OTR Query message to the correspondent of the given
 * conversation. */
void otrg_plugin_send_default_query_conv(PurpleConversation *conv)
{
    PurpleAccount *account;
    const char *username, *accountname;
    char *msg;
    OtrgUiPrefs prefs;
    
    account = purple_conversation_get_account(conv);
    accountname = purple_account_get_username(account);
    username = purple_conversation_get_name(conv);
    
    otrg_ui_get_prefs(&prefs, account, username);
    msg = otrl_proto_default_query_msg(accountname, prefs.policy);
    otrg_plugin_inject_message(account, username, msg ? msg : "?OTRv2?");
    free(msg);
}

static gboolean process_receiving_im(PurpleAccount *account, char **who, 
        char **message, int *flags, void *m)
{
    char *newmessage = NULL;
    OtrlTLV *tlvs = NULL;
    OtrlTLV *tlv = NULL;
    char *username;
    gboolean res;
    const char *accountname;
    const char *protocol;
    ConnContext *context;
    NextExpectedSMP nextMsg;

    if (!who || !*who || !message || !*message)
        return 0;

    username = strdup(purple_normalize(account, *who));
    accountname = purple_account_get_username(account);
    protocol = purple_account_get_protocol_id(account);

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
	otrg_dialog_finished(accountname, protocol, username);
	otrg_ui_update_keylist();
    }

    /* Keep track of our current progress in the Socialist Millionaires'
     * Protocol. */
    context = otrl_context_find(otrg_plugin_userstate, username,
	    accountname, protocol, 0, NULL, NULL, NULL);
    if (context) {
	nextMsg = context->smstate->nextExpected;

	tlv = otrl_tlv_find(tlvs, OTRL_TLV_SMP1);
	if (tlv) {
	    if (nextMsg != OTRL_SMP_EXPECT1)
		otrg_plugin_abort_smp(context);
	    else {
		otrg_dialog_socialist_millionaires(context);
	    }
	}
	tlv = otrl_tlv_find(tlvs, OTRL_TLV_SMP2);
	if (tlv) {
	    if (nextMsg != OTRL_SMP_EXPECT2)
		otrg_plugin_abort_smp(context);
	    else {
		otrg_dialog_update_smp(context, 0.6);
		context->smstate->nextExpected = OTRL_SMP_EXPECT4;
	    }
	}
	tlv = otrl_tlv_find(tlvs, OTRL_TLV_SMP3);
	if (tlv) {
	    if (nextMsg != OTRL_SMP_EXPECT3)
		otrg_plugin_abort_smp(context);
	    else {
		otrg_dialog_update_smp(context, 1.0);
		context->smstate->nextExpected = OTRL_SMP_EXPECT1;
	    }
	}
	tlv = otrl_tlv_find(tlvs, OTRL_TLV_SMP4);
	if (tlv) {
	    if (nextMsg != OTRL_SMP_EXPECT4)
		otrg_plugin_abort_smp(context);
	    else {
		otrg_dialog_update_smp(context, 1.0);
		context->smstate->nextExpected = OTRL_SMP_EXPECT1;
	    }
	}
	tlv = otrl_tlv_find(tlvs, OTRL_TLV_SMP_ABORT);
	if (tlv) {
	    otrg_dialog_update_smp(context, 0.0);
	    context->smstate->nextExpected = OTRL_SMP_EXPECT1;
	}
	
	otrl_tlv_free(tlvs);
    }

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

static void process_conv_create(PurpleConversation *conv, void *data)
{
    if (conv) otrg_dialog_new_conv(conv);
}

static void process_conv_updated(PurpleConversation *conv,
	PurpleConvUpdateType type, void *data)
{
    /* See if someone's trying to turn logging on for this conversation,
     * and we don't want them to. */
    if (type == PURPLE_CONV_UPDATE_LOGGING) {
	ConnContext *context;
	OtrgUiPrefs prefs;
	PurpleAccount *account = purple_conversation_get_account(conv);
	otrg_ui_get_prefs(&prefs, account, purple_conversation_get_name(conv));

	context = otrg_plugin_conv_to_context(conv);
	if (context && prefs.avoid_logging_otr &&
		context->msgstate == OTRL_MSGSTATE_ENCRYPTED &&
		conv->logging == TRUE) {
	    purple_conversation_set_logging(conv, FALSE);
	}
    }
}

static void process_connection_change(PurpleConnection *conn, void *data)
{
    /* If we log in or out of a connection, make sure all of the OTR
     * buttons are in the appropriate sensitive/insensitive state. */
    otrg_dialog_resensitize_all();
}

static void otr_options_cb(PurpleBlistNode *node, gpointer user_data)
{
    /* We've already checked PURPLE_BLIST_NODE_IS_BUDDY(node) */
    PurpleBuddy *buddy = (PurpleBuddy *)node;

    /* Modify the settings for this buddy */
    otrg_ui_config_buddy(buddy);
}

static void supply_extended_menu(PurpleBlistNode *node, GList **menu)
{
    PurpleMenuAction *act;
    PurpleBuddy *buddy;
    PurpleAccount *acct;
    const char *proto;

    if (!PURPLE_BLIST_NODE_IS_BUDDY(node)) return;

    /* Extract the account, and then the protocol, for this buddy */
    buddy = (PurpleBuddy *)node;
    acct = buddy->account;
    if (acct == NULL) return;
    proto = purple_account_get_protocol_id(acct);
    if (!otrg_plugin_proto_supports_otr(proto)) return;

    act = purple_menu_action_new(_("OTR Settings"),
	    (PurpleCallback)otr_options_cb, NULL, NULL);
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
    FILE *storef;
    gchar *storefile = g_build_filename(purple_user_dir(), STOREFNAME, NULL);
    storef = g_fopen(storefile, "wb");
    g_free(storefile);
    if (!storef) return;
    otrl_privkey_write_fingerprints_FILEp(otrg_plugin_userstate, storef);
    fclose(storef);
}

/* Find the ConnContext appropriate to a given PurpleConversation. */
ConnContext *otrg_plugin_conv_to_context(PurpleConversation *conv)
{
    PurpleAccount *account;
    char *username;
    const char *accountname, *proto;
    ConnContext *context;

    account = purple_conversation_get_account(conv);
    accountname = purple_account_get_username(account);
    proto = purple_account_get_protocol_id(account);
    username = g_strdup(
	    purple_normalize(account, purple_conversation_get_name(conv)));

    context = otrl_context_find(otrg_plugin_userstate, username, accountname,
	    proto, 0, NULL, NULL, NULL);
    g_free(username);

    return context;
}

/* Find the PurpleConversation appropriate to the given userinfo.  If
 * one doesn't yet exist, create it if force_create is true. */
PurpleConversation *otrg_plugin_userinfo_to_conv(const char *accountname,
	const char *protocol, const char *username, int force_create)
{
    PurpleAccount *account;
    PurpleConversation *conv;

    account = purple_accounts_find(accountname, protocol);
    if (account == NULL) return NULL;

    conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM,
	    username, account);
    if (conv == NULL && force_create) {
	conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, account, username);
    }

    return conv;
}

/* Find the PurpleConversation appropriate to the given ConnContext.  If
 * one doesn't yet exist, create it if force_create is true. */
PurpleConversation *otrg_plugin_context_to_conv(ConnContext *context,
	int force_create)
{
    return otrg_plugin_userinfo_to_conv(context->accountname,
	    context->protocol, context->username, force_create);
}

/* What level of trust do we have in the privacy of this ConnContext? */
TrustLevel otrg_plugin_context_to_trust(ConnContext *context)
{
    TrustLevel level = TRUST_NOT_PRIVATE;

    if (context && context->msgstate == OTRL_MSGSTATE_ENCRYPTED) {
	if (context->active_fingerprint->trust &&
		context->active_fingerprint->trust[0] != '\0') {
	    level = TRUST_PRIVATE;
	} else {
	    level = TRUST_UNVERIFIED;
	}
    } else if (context && context->msgstate == OTRL_MSGSTATE_FINISHED) {
	level = TRUST_FINISHED;
    }

    return level;
}

/* Send the OTRL_TLV_DISCONNECTED packets when we're about to quit. */
static void process_quitting(void)
{
    ConnContext *context = otrg_plugin_userstate->context_root;
    while(context) {
	ConnContext *next = context->next;
	if (context->msgstate == OTRL_MSGSTATE_ENCRYPTED &&
		context->protocol_version > 1) {
	    otrg_plugin_disconnect(context);
	}
	context = next;
    }
}

/* Read the maxmsgsizes from a FILE* into the given GHashTable.
 * The FILE* must be open for reading. */
static void mms_read_FILEp(FILE *mmsf, GHashTable *ght)
{
    char storeline[50];
    size_t maxsize = sizeof(storeline);

    if (!mmsf) return;

    while(fgets(storeline, maxsize, mmsf)) {
	char *protocol;
	char *prot_in_table;
	char *mms;
	int *mms_in_table;
	char *tab;
	char *eol;
	/* Parse the line, which should be of the form:
	 *    protocol\tmaxmsgsize\n          */
	protocol = storeline;
	tab = strchr(protocol, '\t');
	if (!tab) continue;
	*tab = '\0';

	mms = tab + 1;
	tab = strchr(mms, '\t');
	if (tab) continue;
        eol = strchr(mms, '\r');
	if (!eol) eol = strchr(mms, '\n');
	if (!eol) continue;
	*eol = '\0';
	
	prot_in_table = strdup(protocol);
	mms_in_table = malloc(sizeof(int));
	*mms_in_table = atoi(mms);
	g_hash_table_insert(ght, prot_in_table, mms_in_table);
    }
}

static void otrg_str_free(gpointer data)
{
    g_free((char*)data);
}

static void otrg_int_free(gpointer data)
{
    g_free((int*)data);
}

static void otrg_init_mms_table()
{
    /* Hardcoded defaults for maximum message sizes for various
     * protocols.  These can be overridden in the user's MAXMSGSIZEFNAME
     * file. */
    static const struct s_OtrgIdProtPair {
        char *protid;
	int maxmsgsize;
    } mmsPairs[8] = {{"prpl-msn", 1409}, {"prpl-icq", 2346},
	{"prpl-aim", 2343}, {"prpl-yahoo", 832}, {"prpl-gg", 1999},
	{"prpl-irc", 417}, {"prpl-oscar", 2343}, {NULL, 0}};
    int i = 0;
    gchar *maxmsgsizefile;
    FILE *mmsf;

    mms_table = g_hash_table_new_full(g_str_hash, g_str_equal,
	    otrg_str_free, otrg_int_free);

    for (i=0; mmsPairs[i].protid != NULL; i++) {
    	char* nextprot = g_strdup(mmsPairs[i].protid);
    	int* nextsize = g_malloc(sizeof(int));
    	*nextsize = mmsPairs[i].maxmsgsize;
    	g_hash_table_insert(mms_table, nextprot, nextsize);
    }

    maxmsgsizefile = g_build_filename(purple_user_dir(),
	    MAXMSGSIZEFNAME, NULL);

    if (maxmsgsizefile) {
	mmsf = g_fopen(maxmsgsizefile, "rt");
	/* Actually read the file here */
	if (mmsf) {
	    mms_read_FILEp(mmsf, mms_table);
	    fclose(mmsf);
	}
	g_free(maxmsgsizefile);
    }
}

static void otrg_free_mms_table()
{
    g_hash_table_destroy(mms_table);
}

static gboolean otr_plugin_load(PurplePlugin *handle)
{
    gchar *privkeyfile = g_build_filename(purple_user_dir(), PRIVKEYFNAME,
	    NULL);
    gchar *storefile = g_build_filename(purple_user_dir(), STOREFNAME, NULL);
    void *conv_handle = purple_conversations_get_handle();
    void *conn_handle = purple_connections_get_handle();
    void *blist_handle = purple_blist_get_handle();
    void *core_handle = purple_get_core();
    FILE *privf;
    FILE *storef;

    if (!privkeyfile || !storefile) {
	g_free(privkeyfile);
	g_free(storefile);
	return 0;
    }

    privf = g_fopen(privkeyfile, "rb");
    storef = g_fopen(storefile, "rb");
    g_free(privkeyfile);
    g_free(storefile);

    otrg_init_mms_table();

    otrg_plugin_handle = handle;

    /* Make our OtrlUserState; we'll only use the one. */
    otrg_plugin_userstate = otrl_userstate_create();

    otrl_privkey_read_FILEp(otrg_plugin_userstate, privf);
    otrl_privkey_read_fingerprints_FILEp(otrg_plugin_userstate, storef,
	    NULL, NULL);
    if (privf) fclose(privf);
    if (storef) fclose(storef);

    otrg_ui_update_fingerprint();

    purple_signal_connect(core_handle, "quitting", otrg_plugin_handle,
	    PURPLE_CALLBACK(process_quitting), NULL);
    purple_signal_connect(conv_handle, "sending-im-msg", otrg_plugin_handle,
            PURPLE_CALLBACK(process_sending_im), NULL);
    purple_signal_connect(conv_handle, "receiving-im-msg", otrg_plugin_handle,
            PURPLE_CALLBACK(process_receiving_im), NULL);
    purple_signal_connect(conv_handle, "conversation-updated",
	    otrg_plugin_handle, PURPLE_CALLBACK(process_conv_updated), NULL);
    purple_signal_connect(conv_handle, "conversation-created",
	    otrg_plugin_handle, PURPLE_CALLBACK(process_conv_create), NULL);
    purple_signal_connect(conn_handle, "signed-on", otrg_plugin_handle,
	    PURPLE_CALLBACK(process_connection_change), NULL);
    purple_signal_connect(conn_handle, "signed-off", otrg_plugin_handle,
	    PURPLE_CALLBACK(process_connection_change), NULL);
    purple_signal_connect(blist_handle, "blist-node-extended-menu",
	    otrg_plugin_handle, PURPLE_CALLBACK(supply_extended_menu), NULL);

    otrg_ui_init();
    otrg_dialog_init();

    purple_conversation_foreach(otrg_dialog_new_conv);

    return 1;
}

static gboolean otr_plugin_unload(PurplePlugin *handle)
{
    void *conv_handle = purple_conversations_get_handle();
    void *conn_handle = purple_connections_get_handle();
    void *blist_handle = purple_blist_get_handle();
    void *core_handle = purple_get_core();

    /* Clean up all of our state. */
    otrl_userstate_free(otrg_plugin_userstate);
    otrg_plugin_userstate = NULL;

    otrg_free_mms_table();

    purple_signal_disconnect(core_handle, "quitting", otrg_plugin_handle,
	    PURPLE_CALLBACK(process_quitting));
    purple_signal_disconnect(conv_handle, "sending-im-msg",
	    otrg_plugin_handle, PURPLE_CALLBACK(process_sending_im));
    purple_signal_disconnect(conv_handle, "receiving-im-msg",
	    otrg_plugin_handle, PURPLE_CALLBACK(process_receiving_im));
    purple_signal_disconnect(conv_handle, "conversation-updated",
	    otrg_plugin_handle, PURPLE_CALLBACK(process_conv_updated));
    purple_signal_disconnect(conv_handle, "conversation-created",
	    otrg_plugin_handle, PURPLE_CALLBACK(process_conv_create));
    purple_signal_disconnect(conn_handle, "signed-on", otrg_plugin_handle,
	    PURPLE_CALLBACK(process_connection_change));
    purple_signal_disconnect(conn_handle, "signed-off", otrg_plugin_handle,
	    PURPLE_CALLBACK(process_connection_change));
    purple_signal_disconnect(blist_handle, "blist-node-extended-menu",
	    otrg_plugin_handle, PURPLE_CALLBACK(supply_extended_menu));

    purple_conversation_foreach(otrg_dialog_remove_conv);

    otrg_dialog_cleanup();
    otrg_ui_cleanup();

    return 1;
}

/* Return 1 if the given protocol supports OTR, 0 otherwise. */
int otrg_plugin_proto_supports_otr(const char *proto)
{
    /* Right now, OTR should work on all protocols, possibly
     * with the help of fragmentation. */
    return 1;
}

#ifdef USING_GTK

static PidginPluginUiInfo ui_info =
{
	otrg_gtk_ui_make_widget
};

#define UI_INFO &ui_info
#define PLUGIN_TYPE PIDGIN_PLUGIN_TYPE

#else

#define UI_INFO NULL
#define PLUGIN_TYPE ""

#endif

static PurplePluginInfo info =
{
	PURPLE_PLUGIN_MAGIC,

        /* Use the 2.0.x API */
        2,                                                /* major version  */
	0,                                                /* minor version  */

	PURPLE_PLUGIN_STANDARD,                           /* type           */
	PLUGIN_TYPE,                                      /* ui_requirement */
	0,                                                /* flags          */
	NULL,                                             /* dependencies   */
	PURPLE_PRIORITY_DEFAULT,                          /* priority       */
	"otr",                                            /* id             */
	NULL,                                             /* name           */
	PIDGIN_OTR_VERSION,                               /* version        */
	NULL,                                             /* summary        */
	NULL,                                             /* description    */
	                                                  /* author         */
	"Ian Goldberg, Chris Alexander, Nikita Borisov\n"
	    "\t\t\t<otr@cypherpunks.ca>",
	"http://otr.cypherpunks.ca/",                     /* homepage       */

	otr_plugin_load,                                  /* load           */
	otr_plugin_unload,                                /* unload         */
	NULL,                                             /* destroy        */

	UI_INFO,                                          /* ui_info        */
	NULL,                                             /* extra_info     */
	NULL,                                             /* prefs_info     */
	NULL                                              /* actions        */
};

static void
__init_plugin(PurplePlugin *plugin)
{
    /* Set up the UI ops */
#ifdef USING_GTK
    otrg_ui_set_ui_ops(otrg_gtk_ui_get_ui_ops());
    otrg_dialog_set_ui_ops(otrg_gtk_dialog_get_ui_ops());
#endif

    /* Initialize the OTR library */
    OTRL_INIT;

#ifdef ENABLE_NLS
    bindtextdomain(GETTEXT_PACKAGE, LOCALEDIR);
    bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8");
#endif

    info.name        = _("Off-the-Record Messaging");
    info.summary     = _("Provides private and secure conversations");
    info.description = _("Preserves the privacy of IM communications "
                         "by providing encryption, authentication, "
			 "deniability, and perfect forward secrecy.");
}

PURPLE_INIT_PLUGIN(otr, __init_plugin, info)
