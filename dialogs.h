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

#ifndef __OTRG_DIALOGS_H__
#define __OTRG_DIALOGS_H__

/* gaim headers */
#include "notify.h"

/* libotr headers */
#include <libotr/proto.h>
#include <libotr/message.h>

/* The various help URLs */
#define BASE_HELPURL "http://otr-help.cypherpunks.ca/"
#define FINGERPRINT_HELPURL   BASE_HELPURL "fingerprint.php"
#define SESSIONID_HELPURL     BASE_HELPURL "sessionid.php"
#define UNVERIFIED_HELPURL    BASE_HELPURL "unverified.php"
#define BUTTON_HELPURL        BASE_HELPURL "buttonhelp.php"

typedef struct s_OtrgDialogWait *OtrgDialogWaitHandle;

typedef struct {
    void (*notify_message)(GaimNotifyMsgType type,
	const char *accountname, const char *protocol, const char *username,
	const char *title, const char *primary, const char *secondary);

    int (*display_otr_message)(const char *accountname, const char *protocol,
	    const char *username, const char *msg);

    OtrgDialogWaitHandle (*private_key_wait_start)(const char *account,
	const char *protocol);

    void (*private_key_wait_done)(OtrgDialogWaitHandle handle);

    void (*unknown_fingerprint)(OtrlUserState us, const char *accountname,
	const char *protocol, const char *who, unsigned char fingerprint[20]);

    void (*verify_fingerprint)(Fingerprint *fprint);

    void (*connected)(ConnContext *context);

    void (*disconnected)(ConnContext *context);

    void (*stillconnected)(ConnContext *context);

    void (*finished)(const char *accountname, const char *protocol,
	    const char *username);

    void (*resensitize_all)(void);

    void (*new_conv)(GaimConversation *conv);

    void (*remove_conv)(GaimConversation *conv);
} OtrgDialogUiOps;

/* Set the UI ops */
void otrg_dialog_set_ui_ops(const OtrgDialogUiOps *ops);

/* Get the UI ops */
const OtrgDialogUiOps *otrg_dialog_get_ui_ops(void);

/* This is just like gaim_notify_message, except: (a) it doesn't grab
 * keyboard focus, (b) the button is "OK" instead of "Close", and (c)
 * the labels aren't limited to 2K. */
void otrg_dialog_notify_message(GaimNotifyMsgType type,
	const char *accountname, const char *protocol, const char *username,
	const char *title, const char *primary, const char *secondary);

/* Put up the error version of otrg_dialog_notify_message */
void otrg_dialog_notify_error(const char *accountname, const char *protocol,
	const char *username, const char *title, const char *primary,
	const char *secondary);

/* Put up the warning version of otrg_dialog_notify_message */
void otrg_dialog_notify_warning(const char *accountname, const char *protocol,
	const char *username, const char *title, const char *primary,
	const char *secondary);

/* Put up the info version of otrg_dialog_notify_message */
void otrg_dialog_notify_info(const char *accountname, const char *protocol,
	const char *username, const char *title, const char *primary,
	const char *secondary);

/* Display an OTR control message for the given accountname / protocol /
 * username conversation.  Return 0 on success, non-0 on error (in which
 * case the message will be displayed inline as a received message). */
int otrg_dialog_display_otr_message( const char *accountname,
	const char *protocol, const char *username, const char *msg);

/* Put up a Please Wait dialog. This dialog can not be cancelled.
 * Return a handle that must eventually be passed to
 * otrg_dialog_private_key_wait_done. */
OtrgDialogWaitHandle otrg_dialog_private_key_wait_start(const char *account,
	const char *protocol);

/* End a Please Wait dialog. */
void otrg_dialog_private_key_wait_done(OtrgDialogWaitHandle handle);

/* Show a dialog informing the user that a correspondent (who) has sent
 * us a Key Exchange Message (kem) that contains an unknown fingerprint. */
void otrg_dialog_unknown_fingerprint(OtrlUserState us, const char *accountname,
	const char *protocol, const char *who, unsigned char fingerprint[20]);

/* Show a dialog asking the user to verify the given fingerprint. */
void otrg_dialog_verify_fingerprint(Fingerprint *fprint);

/* Call this when a context transitions to ENCRYPTED. */
void otrg_dialog_connected(ConnContext *context);

/* Call this when a context transitions to PLAINTEXT. */
void otrg_dialog_disconnected(ConnContext *context);

/* Call this when we receive a Key Exchange message that doesn't cause
 * our state to change (because it was just the keys we knew already). */
void otrg_dialog_stillconnected(ConnContext *context);

/* Call this if the remote user terminates his end of an ENCRYPTED
 * connection, and lets us know. */
void otrg_dialog_finished(const char *accountname, const char *protocol,
	const char *username);

/* Set all OTR buttons to "sensitive" or "insensitive" as appropriate.
 * Call this when accounts are logged in or out. */
void otrg_dialog_resensitize_all(void);

/* Set up the per-conversation information display */
void otrg_dialog_new_conv(GaimConversation *conv);

/* Remove the per-conversation information display */
void otrg_dialog_remove_conv(GaimConversation *conv);

#endif
