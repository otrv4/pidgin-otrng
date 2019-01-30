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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <dialogs.h>

/* system headers */
#include <stdlib.h>

static const OtrgDialogUiOps *ui_ops = NULL;

/* Set the UI ops */
void otrng_dialog_set_ui_ops(const OtrgDialogUiOps *ops) { ui_ops = ops; }

/* Get the UI ops */
const OtrgDialogUiOps *otrng_dialog_get_ui_ops(void) { return ui_ops; }

/* Initialize the OTR dialog subsystem */
void otrng_dialog_init(void) { ui_ops->init(); }

/* Deinitialize the OTR dialog subsystem */
void otrng_dialog_cleanup(void) { ui_ops->cleanup(); }

/* This is just like pidgin_notify_message, except: (a) it doesn't grab
 * keyboard focus, (b) the button is "OK" instead of "Close", and (c)
 * the labels aren't limited to 2K. */
void otrng_dialog_notify_message(PurpleNotifyMsgType type,
                                 const char *accountname, const char *protocol,
                                 const char *username, const char *title,
                                 const char *primary, const char *secondary) {
  ui_ops->notify_message(type, accountname, protocol, username, title, primary,
                         secondary);
}

/* Put up the error version of otrng_dialog_notify_message */
void otrng_dialog_notify_error(const char *accountname, const char *protocol,
                               const char *username, const char *title,
                               const char *primary, const char *secondary) {
  otrng_dialog_notify_message(PURPLE_NOTIFY_MSG_ERROR, accountname, protocol,
                              username, title, primary, secondary);
}

/* Put up the warning version of otrng_dialog_notify_message */
void otrng_dialog_notify_warning(const char *accountname, const char *protocol,
                                 const char *username, const char *title,
                                 const char *primary, const char *secondary) {
  otrng_dialog_notify_message(PURPLE_NOTIFY_MSG_WARNING, accountname, protocol,
                              username, title, primary, secondary);
}

/* Put up the info version of otrng_dialog_notify_message */
void otrng_dialog_notify_info(const char *accountname, const char *protocol,
                              const char *username, const char *title,
                              const char *primary, const char *secondary) {
  otrng_dialog_notify_message(PURPLE_NOTIFY_MSG_INFO, accountname, protocol,
                              username, title, primary, secondary);
}

/* Display an OTR control message for the given accountname / protocol /
 * username conversation.  Return 0 on success, non-0 on error (in which
 * case the message will be displayed inline as a received message). */
int otrng_dialog_display_otr_message(const char *accountname,
                                     const char *protocol, const char *username,
                                     const char *msg, int force_create) {
  return ui_ops->display_otr_message(accountname, protocol, username, msg,
                                     force_create);
}

/* Put up a Please Wait dialog.  This dialog can not be cancelled.
 * Return a handle that must eventually be passed to
 * otrng_dialog_private_key_wait_done. */
OtrgDialogWaitHandle otrng_dialog_private_key_wait_start(const char *account,
                                                         const char *protocol) {
  return ui_ops->private_key_wait_start(account, protocol);
}

/* End a Please Wait dialog. */
void otrng_dialog_private_key_wait_done(OtrgDialogWaitHandle handle) {
  ui_ops->private_key_wait_done(handle);
}

/* Show a dialog informing the user that a correspondent (who) has sent
 * us a Key Exchange Message (kem) that contains an unknown fingerprint. */
void otrng_dialog_unknown_fingerprint(OtrlUserState us, const char *accountname,
                                      const char *protocol, const char *who,
                                      const unsigned char fingerprint[20]) {
  ui_ops->unknown_fingerprint(us, accountname, protocol, who, fingerprint);
}

/* Show a dialog asking the user to verify the given fingerprint. */
void otrng_dialog_verify_fingerprint(otrng_client_id_s client_id,
                                     otrng_plugin_fingerprint_s *fprint) {
  ui_ops->verify_fingerprint(client_id, fprint);
}

/* Show a dialog asking the user to give an SMP secret. */
void otrng_dialog_socialist_millionaires(
    const otrng_plugin_conversation *conv) {
  ui_ops->socialist_millionaires(conv, NULL, TRUE);
}

/* Show a dialog asking the user to give an SMP secret, prompting with a
 * question. */
void otrng_dialog_socialist_millionaires_q(
    const otrng_plugin_conversation *conv, const char *question) {
  ui_ops->socialist_millionaires(conv, question, TRUE);
}

/* Update the status of an ongoing socialist millionaires protocol. */
void otrng_dialog_update_smp(const otrng_plugin_conversation *context,
                             otrng_smp_event smp_event, double progress_level) {
  ui_ops->update_smp(context, smp_event, progress_level);
}

void otrng_dialog_conversation_connected(otrng_plugin_conversation *conv) {
  ui_ops->connected(conv);
}

/* Call this when a context transitions to ENCRYPTED. */
void otrng_dialog_connected(ConnContext *context) {
  otrng_plugin_conversation conv;
  conv.account = context->accountname;
  conv.protocol = context->protocol;
  conv.peer = context->username;
  otrng_dialog_conversation_connected(&conv);
}

void otrng_dialog_conversation_disconnected(
    const otrng_plugin_conversation *conv) {
  ui_ops->disconnected(conv);
}

/* Call this when a context transitions to PLAINTEXT. */
void otrng_dialog_disconnected(ConnContext *context) {
  otrng_plugin_conversation conv;
  conv.account = context->accountname;
  conv.protocol = context->protocol;
  conv.peer = context->username;

  otrng_dialog_conversation_disconnected(&conv);
}

/* Call this when we receive a Key Exchange message that doesn't cause
 * our state to change (because it was just the keys we knew already). */
void otrng_dialog_stillconnected(ConnContext *context) {
  ui_ops->stillconnected(context);
}

/* Call this if the remote user terminates his end of an ENCRYPTED
 * connection, and lets us know. */
void otrng_dialog_finished(const char *accountname, const char *protocol,
                           const char *username) {
  ui_ops->finished(accountname, protocol, username);
}

/* Set all OTR buttons to "sensitive" or "insensitive" as appropriate.
 * Call this when accounts are logged in or out. */
void otrng_dialog_resensitize_all(void) { ui_ops->resensitize_all(); }

/* Set up the per-conversation information display */
void otrng_dialog_new_conv(PurpleConversation *conv) { ui_ops->new_conv(conv); }

/* Remove the per-conversation information display */
void otrng_dialog_remove_conv(PurpleConversation *conv) {
  ui_ops->remove_conv(conv);
}
