/*
 *  Off-the-Record Messaging plugin for pidgin
 *  Copyright (C) 2004-2012  Ian Goldberg, Rob Smits,
 *                           Chris Alexander, Willy Lew,
 *                           Nikita Borisov
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

/* config.h */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* system headers */
#include <stdlib.h>

/* purple headers */
#include "util.h"
#include "account.h"

#ifdef ENABLE_NLS
/* internationalisation header */
#include <glib/gi18n-lib.h>
#else
#define _(x) (x)
#define N_(x) (x)
#endif

/* libotr headers */
#include <libotr/privkey.h>
#include <libotr/proto.h>
#include <libotr/message.h>

/* purple-otr headers */
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

/* Initialize the OTR UI subsystem */
void otrg_ui_init(void)
{
    if (ui_ops != NULL) {
	ui_ops->init();
    }
}

/* Deinitialize the OTR UI subsystem */
void otrg_ui_cleanup(void)
{
    if (ui_ops != NULL) {
	ui_ops->cleanup();
    }
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

/* Drop a context to PLAINTEXT state */
void otrg_ui_disconnect_connection(otrg_plugin_conversation *conv)
{
    otr4_client_adapter_t* client = otr4_client(conv->protocol, conv->account);
    if (!client)
        return;

    otr4_conversation_t *otr_conv = otr4_client_get_conversation(0,
        conv->peer, client->real_client);

    /* Don't do anything with fingerprints other than the active one
     * if we're in the ENCRYPTED state */
    if (otr_conv && otr_conv->conn->state == OTRV4_STATE_ENCRYPTED_MESSAGES){
        otrg_plugin_disconnect(conv);

        //TODO: We call gone_insecure when we close.
        //libotr DOES NOT.
        //otrg_dialog_disconnected(context);
    }
}

//TODO: should not this be in another file?
/* Forget a fingerprint */
void otrg_ui_forget_fingerprint(otrg_plugin_fingerprint *fingerprint)
{
    if (fingerprint == NULL) return;

    otr4_conversation_t *otr_conv = otrg_plugin_fingerprint_to_otr_conversation(fingerprint);

    /* Don't do anything with the active fingerprint if we're in the
     * ENCRYPTED state. */
    if (otr_conv && otr_conv->conn->state == OTRV4_STATE_ENCRYPTED_MESSAGES) return;

    otrg_plugin_fingerprint_forget(fingerprint->fp);
    otrg_plugin_write_fingerprints();

    otrg_ui_update_keylist();
}

/* Configure OTR for a particular buddy */
void otrg_ui_config_buddy(PurpleBuddy *buddy)
{
    if (ui_ops != NULL) {
	ui_ops->config_buddy(buddy);
    }
}

/* Load the preferences for a particular account / username */
void otrg_ui_get_prefs(OtrgUiPrefs *prefsp, PurpleAccount *account,
	const char *name)
{
    /* Check to see if the protocol for this account supports OTR at all. */
    const char *proto = purple_account_get_protocol_id(account);
    if (!otrg_plugin_proto_supports_otr(proto)) {
	prefsp->policy = OTRL_POLICY_NEVER;
	prefsp->avoid_logging_otr = TRUE;
	prefsp->show_otr_button = FALSE;
	return;
    }

    if (ui_ops != NULL) {
	ui_ops->get_prefs(prefsp, account, name);
	return;
    }
    /* If we've got no other way to get the prefs, use sensible defaults */
    prefsp->policy = OTRL_POLICY_DEFAULT;
    prefsp->avoid_logging_otr = TRUE;
    prefsp->show_otr_button = FALSE;
}
