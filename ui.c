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

/* system headers */
#include <stdlib.h>

/* gaim headers */
#include "util.h"
#include "account.h"

/* libotr headers */
#include <libotr/privkey.h>
#include <libotr/proto.h>
#include <libotr/message.h>

/* gaim-otr headers */
#include "ui.h"
#include "dialogs.h"
#include "otr-plugin.h"

static const OtrgUiUiOps *ui_ops = NULL;

/* Set the UI ops */
void otrg_ui_set_ui_ops(const OtrgUiUiOps *ops)
{
    ui_ops = ops;
}

/* Get the UI ops */
const OtrgUiUiOps *otrg_ui_get_ui_ops(void)
{
    return ui_ops;
}

/* Call this function when the DSA key is updated; it will redraw the
 * UI, if visible. */
void otrg_ui_update_fingerprint(void)
{
    if (ui_ops != NULL) {
	ui_ops->update_fingerprint();
    }
}

/* Update the keylist, if it's visible */
void otrg_ui_update_keylist(void)
{
    if (ui_ops != NULL) {
	ui_ops->update_keylist();
    }
}

/* Send an OTR Query Message to attempt to start a connection */
void otrg_ui_connect_connection(ConnContext *context)
{
    /* Send an OTR Query to the other side. */
    GaimAccount *account;
    char *msg;
	
    /* Only do anything for UNCONNECTED fingerprints */
    if (context == NULL || context->state != CONN_UNCONNECTED) return;
	
    account = gaim_accounts_find(context->accountname, context->protocol);
    if (!account) {
	GaimPlugin *p = gaim_find_prpl(context->protocol);
	msg = g_strdup_printf("Account %s (%s) could not be found",
		  context->accountname,
		  (p && p->info->name) ? p->info->name : "Unknown");
	otrg_dialog_notify_error(context->accountname, context->protocol,
		context->username, "Account not found", msg, NULL);
	g_free(msg);
	return;
    }
    otrg_plugin_send_default_query(context, account);	
}

/* Drop a context to UNCONNECTED state */
void otrg_ui_disconnect_connection(ConnContext *context)
{
    /* Don't do anything with UNCONNECTED fingerprints */
    if (context == NULL || context->state == CONN_UNCONNECTED) return;
		
    otrg_plugin_disconnect(context);
    otrg_dialog_disconnected(context);	
}

/* Forget a fingerprint */
void otrg_ui_forget_fingerprint(Fingerprint *fingerprint)
{
    ConnContext *context;
    gchar *storefile;
	
    if (fingerprint == NULL) return;

    /* Don't do anything with the active fingerprint if we're in the
     * CONNECTED state. */
    context = fingerprint->context;
    if (context->state == CONN_CONNECTED &&
	    context->active_fingerprint == fingerprint) return;
	
    otrl_context_forget_fingerprint(fingerprint, 1);
    storefile = g_build_filename(gaim_user_dir(), STOREFNAME, NULL);
    otrl_privkey_write_fingerprints(otrg_plugin_userstate, storefile);
    g_free(storefile);
	
    otrg_ui_update_keylist();
}

/* Configure OTR for a particular buddy */
void otrg_ui_config_buddy(GaimBuddy *buddy)
{
    if (ui_ops != NULL) {
	ui_ops->config_buddy(buddy);
    }
}

/* Calculate the policy for a particular account / username */
OtrlPolicy otrg_ui_find_policy(GaimAccount *account, const char *name)
{
    /* Check to see if the protocol for this account supports OTR at all. */
    const char *proto = gaim_account_get_protocol_id(account);
    if (!otrg_plugin_proto_supports_otr(proto)) {
	return OTRL_POLICY_NEVER;
    }

    if (ui_ops != NULL) {
	return ui_ops->find_policy(account, name);
    }
    return OTRL_POLICY_DEFAULT;
}
