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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* system headers */
#include <stdlib.h>

/* gaim headers */
#include "notify.h"

/* libotr headers */
#include <libotr/proto.h>
#include <libotr/message.h>

/* gaim-otr headers */
#include "dialogs.h"
#include "otr-plugin.h"

static const OtrgDialogUiOps *ui_ops = NULL;

/* Set the UI ops */
void otrg_dialog_set_ui_ops(const OtrgDialogUiOps *ops)
{
    ui_ops = ops;
}

/* Get the UI ops */
const OtrgDialogUiOps *otrg_dialog_get_ui_ops(void)
{
    return ui_ops;
}

/* This is just like gaim_notify_message, except: (a) it doesn't grab
 * keyboard focus, (b) the button is "OK" instead of "Close", and (c)
 * the labels aren't limited to 2K. */
void otrg_dialog_notify_message(GaimNotifyMsgType type,
	const char *accountname, const char *protocol, const char *username,
	const char *title, const char *primary, const char *secondary)
{
    ui_ops->notify_message(type, accountname, protocol, username,
	    title, primary, secondary);
}

/* Put up the error version of otrg_dialog_notify_message */
void otrg_dialog_notify_error(const char *accountname, const char *protocol,
	const char *username, const char *title, const char *primary,
	const char *secondary)
{
    otrg_dialog_notify_message(GAIM_NOTIFY_MSG_ERROR, accountname,
	    protocol, username, title, primary, secondary);
}

/* Put up the warning version of otrg_dialog_notify_message */
void otrg_dialog_notify_warning(const char *accountname, const char *protocol,
	const char *username, const char *title, const char *primary,
	const char *secondary)
{
    otrg_dialog_notify_message(GAIM_NOTIFY_MSG_WARNING, accountname,
	    protocol, username, title, primary, secondary);
}

/* Put up the info version of otrg_dialog_notify_message */
void otrg_dialog_notify_info(const char *accountname, const char *protocol,
	const char *username, const char *title, const char *primary,
	const char *secondary)
{
    otrg_dialog_notify_message(GAIM_NOTIFY_MSG_INFO, accountname,
	    protocol, username, title, primary, secondary);
}

/* Display an OTR control message for the given accountname / protocol /
 * username conversation.  Return 0 on success, non-0 on error (in which
 * case the message will be displayed inline as a received message). */
int otrg_dialog_display_otr_message( const char *accountname,
	const char *protocol, const char *username, const char *msg)
{
    return ui_ops->display_otr_message(accountname, protocol, username, msg);
}

/* Put up a Please Wait dialog.  This dialog can not be cancelled.
 * Return a handle that must eventually be passed to
 * otrg_dialog_private_key_wait_done. */
OtrgDialogWaitHandle otrg_dialog_private_key_wait_start(const char *account,
	const char *protocol)
{
    return ui_ops->private_key_wait_start(account, protocol);
}

/* End a Please Wait dialog. */
void otrg_dialog_private_key_wait_done(OtrgDialogWaitHandle handle)
{
    ui_ops->private_key_wait_done(handle);
}

/* Show a dialog informing the user that a correspondent (who) has sent
 * us a Key Exchange Message (kem) that contains an unknown fingerprint.
 * Ask the user whether to accept the fingerprint or not.  If yes, call
 * response_cb(us, ops, opdata, response_data, resp) with resp = 1.  If no,
 * set resp = 0.  If the user destroys the dialog without answering, set
 * resp = -1. */
void otrg_dialog_unknown_fingerprint(OtrlUserState us, const char *accountname,
	const char *protocol, const char *who, OTRKeyExchangeMsg kem,
	void (*response_cb)(OtrlUserState us, OtrlMessageAppOps *ops,
	    void *opdata, OTRConfirmResponse *response_data, int resp),
	OtrlMessageAppOps *ops, void *opdata,
	OTRConfirmResponse *response_data)
{
    ui_ops->unknown_fingerprint(us, accountname, protocol, who, kem,
	    response_cb, ops, opdata, response_data);
}

/* Call this when a context transitions from (a state other than
 * CONN_CONNECTED) to CONN_CONNECTED. */
void otrg_dialog_connected(ConnContext *context)
{
    ui_ops->connected(context);
}

/* Call this when a context transitions from CONN_CONNECTED to
 * (a state other than CONN_CONNECTED). */
void otrg_dialog_disconnected(ConnContext *context)
{
    ui_ops->disconnected(context);
}

/* Call this when we receive a Key Exchange message that doesn't cause
 * our state to change (because it was just the keys we knew already). */
void otrg_dialog_stillconnected(ConnContext *context)
{
    ui_ops->stillconnected(context);
}

/* Set all OTR buttons to "sensitive" or "insensitive" as appropriate.
 * Call this when accounts are logged in or out. */
void otrg_dialog_resensitize_all(void)
{
    ui_ops->resensitize_all();
}

/* Set up the per-conversation information display */
void otrg_dialog_new_conv(GaimConversation *conv)
{
    ui_ops->new_conv(conv);
}

/* Remove the per-conversation information display */
void otrg_dialog_remove_conv(GaimConversation *conv)
{
    ui_ops->remove_conv(conv);
}
