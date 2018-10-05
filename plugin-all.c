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

/* config.h */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>

/* system headers */
#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* libgcrypt headers */
#include <gcrypt.h>

/* purple headers */
#include <core.h>
#include <debug.h>
#include <notify.h>
#include <pidgin.h>
#include <util.h>
#include <version.h>

#ifdef USING_GTK
/* purple GTK headers */
#include <gtkplugin.h>
#endif

/* libotr headers */
#include <libotr/proto.h>

#include <libotr/instag.h>
#include <libotr/message.h>
#include <libotr/privkey.h>
#include <libotr/tlv.h>
#include <libotr/userstate.h>

/* pidgin-otrng headers */
#include "persistance.h"
#include "plugin-all.h"
#include "prekey-plugin.h"
#include "prekeys.h"
#include "profiles.h"

#ifdef USING_GTK

#include <glib.h>

/* pidgin-otrng GTK headers */
#include "gtk-dialog.h"
#include "gtk-ui.h"
#include "i18n.h"
#include "long_term_keys.h"
#include "pidgin-helpers.h"
#include "prekey-discovery.h"
#include "prekey-plugin-peers.h"
#include "prekey-plugin-shared.h"

#include <libotr-ng/alloc.h>
#include <libotr-ng/client_orchestration.h>
#include <libotr-ng/debug.h>

/* Controls a beta warning/expiry dialog */
#define BETA_DIALOG 0

#if defined USING_GTK
#include "gtkblist.h"
#endif

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

PurplePlugin *otrng_plugin_handle;

otrng_global_state_s *otrng_state = NULL;

/* GLib HashTable for storing the maximum message size for various
 * protocols. */
GHashTable *otrng_max_message_size_table = NULL;

GHashTable *otrng_fingerprints_table = NULL;

static void g_destroy_plugin_fingerprint(gpointer data) {
  otrng_plugin_fingerprint *fp = data;

  free(fp->protocol);
  free(fp->account);
  free(fp->username);
  free(fp);
}

static void otrng_plugin_read_private_keys(FILE *priv3, FILE *priv4) {
  if (!otrng_global_state_private_key_v3_read_from(otrng_state, priv3)) {
    // TODO: error?
  }
}

static void otrng_plugin_read_instance_tags_FILEp(FILE *instagf) {
  if (otrng_failed(
          otrng_global_state_instance_tags_read_from(otrng_state, instagf))) {
    // TODO: react better on failure
    return;
  }
}

static void otrng_plugin_read_expired_client_profile(FILE *profiles_filep) {
  if (otrng_failed(otrng_global_state_expired_client_profile_read_from(
          otrng_state, profiles_filep,
          protocol_and_account_to_purple_conversation))) {
    // TODO: react better on failure
    return;
  }
}

static void otrng_plugin_read_expired_prekey_profile(FILE *profiles_filep) {
  if (otrng_failed(otrng_global_state_expired_prekey_profile_read_from(
          otrng_state, profiles_filep,
          protocol_and_account_to_purple_conversation))) {
    // TODO: react better on failure
    return;
  }
}

static void otrng_plugin_fingerprint_store_create() {
  otrng_fingerprints_table = g_hash_table_new_full(
      g_str_hash, g_str_equal, g_free, g_destroy_plugin_fingerprint);
}

otrng_plugin_fingerprint *
otrng_plugin_fingerprint_get(const char fp[OTRNG_FPRINT_HUMAN_LEN]) {
  return g_hash_table_lookup(otrng_fingerprints_table, fp);
}

otrng_plugin_fingerprint *
otrng_plugin_fingerprint_new(const char fp[OTRNG_FPRINT_HUMAN_LEN],
                             const char *protocol, const char *account,
                             const char *peer) {
  otrng_plugin_fingerprint *info = malloc(sizeof(otrng_plugin_fingerprint));
  if (!info) {
    return NULL;
  }

  info->trusted = 0;
  memcpy(info->fp, fp, OTRNG_FPRINT_HUMAN_LEN);
  info->protocol = g_strdup(protocol);
  info->account = g_strdup(account);
  info->username = g_strdup(peer);

  char *key = g_strdup(fp);
  g_hash_table_insert(otrng_fingerprints_table, key, info);
  return info;
}

/* Send an IM from the given account to the given recipient.  Display an
 * error dialog if that account isn't currently logged in. */
void otrng_plugin_inject_message(PurpleAccount *account, const char *recipient,
                                 const char *message) {
  PurpleConnection *connection;

  connection = purple_account_get_connection(account);
  if (!connection) {
    const char *protocol = purple_account_get_protocol_id(account);
    const char *accountname = purple_account_get_username(account);
    PurplePlugin *p = purple_find_prpl(protocol);
    char *msg = g_strdup_printf(
        _("You are not currently connected to "
          "account %s (%s)."),
        accountname, (p && p->info->name) ? p->info->name : _("Unknown"));
    otrng_dialog_notify_error(accountname, protocol, recipient,
                              _("Not connected"), msg, NULL);
    g_free(msg);
    return;
  }
  serv_send_im(connection, recipient, message, 0);
}

/* Display a notification message for a particular accountname /
 * protocol / username conversation. */
static void notify(void *opdata, OtrlNotifyLevel level, const char *accountname,
                   const char *protocol, const char *username,
                   const char *title, const char *primary,
                   const char *secondary) {
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

  otrng_dialog_notify_message(purplelevel, accountname, protocol, username,
                              title, primary, secondary);
}

/* Display an OTR control message for a particular accountname /
 * protocol / username conversation.  If force_create is non-zero and
 * if the corresponding conversation window is not present, a new
 * conversation window will be created and the message will be displayed
 * there. If the message cannot be displayed, try notify() instead and
 * return 1. Otherwise return 0 if message is successfully displayed. */
static int display_otr_message_or_notify(void *opdata, const char *accountname,
                                         const char *protocol,
                                         const char *username, const char *msg,
                                         int force_create,
                                         OtrlNotifyLevel level,
                                         const char *title, const char *primary,
                                         const char *secondary) {
  if (otrng_dialog_display_otr_message(accountname, protocol, username, msg,
                                       force_create)) {
    notify(opdata, level, accountname, protocol, username, title, primary,
           secondary);
    return 1;
  }
  return 0;
}

static void log_message(void *opdata, const char *message) {
  purple_debug_info("otr", "%s", message);
}

static OtrlPolicy policy_cb(void *opdata, ConnContext *context) {
  PurpleAccount *account;
  OtrlPolicy policy = OTRL_POLICY_DEFAULT;
  OtrgUiPrefs prefs;

  if (!context) {
    return policy;
  }

  account = purple_accounts_find(context->accountname, context->protocol);
  if (!account) {
    return policy;
  }

  otrng_ui_get_prefs(&prefs, account, context->username);
  return prefs.policy;
}

static int otrng_plugin_write_privkey_v3_FILEp(PurpleAccount *account) {
#ifndef WIN32
  mode_t mask;
#endif /* WIN32 */
  FILE *privf;

  gchar *privkeyfile =
      g_build_filename(purple_user_dir(), PRIVKEY_FILE_NAME, NULL);
  if (!privkeyfile) {
    fprintf(stderr, _("Out of memory building filenames!\n"));
    return -1;
  }
#ifndef WIN32
  mask = umask(0077);
#endif /* WIN32 */
  privf = g_fopen(privkeyfile, "w+b");
#ifndef WIN32
  umask(mask);
#endif /* WIN32 */

  g_free(privkeyfile);
  if (!privf) {
    fprintf(stderr, _("Could not write private key file\n"));
    return -1;
  }

  int err = 0;
  if (otrng_failed(otrng_global_state_private_key_v3_generate_into(
          otrng_state, purple_account_to_client_id(account), privf))) {
    err = -1;
  }
  fclose(privf);

  return err;
}

static int otrng_plugin_write_expired_client_profile_FILEp(void) {
#ifndef WIN32
  mode_t mask;
#endif /* WIN32 */
  FILE *filep;

  gchar *file_name =
      g_build_filename(purple_user_dir(), EXP_CLIENT_PROFILE_FILE_NAME, NULL);
  if (!file_name) {
    fprintf(stderr, _("Out of memory building filenames!\n"));
    return -1;
  }
#ifndef WIN32
  mask = umask(0077);
#endif /* WIN32 */
  filep = g_fopen(file_name, "w+b");
#ifndef WIN32
  umask(mask);
#endif /* WIN32 */

  g_free(file_name);
  if (!filep) {
    fprintf(stderr, _("Could not write client profile file\n"));
    return -1;
  }

  int err = 0;
  if (otrng_failed(
          otrng_global_state_client_profile_write_to(otrng_state, filep))) {
    err = -1;
  }
  fclose(filep);

  return err;
}

static int otrng_plugin_write_expired_prekey_profile_FILEp(void) {
#ifndef WIN32
  mode_t mask;
#endif /* WIN32 */
  FILE *filep;

  gchar *file_name =
      g_build_filename(purple_user_dir(), EXP_PREKEY_PROFILE_FILE_NAME, NULL);
  if (!file_name) {
    fprintf(stderr, _("Out of memory building filenames!\n"));
    return -1;
  }
#ifndef WIN32
  mask = umask(0077);
#endif /* WIN32 */
  filep = g_fopen(file_name, "w+b");
#ifndef WIN32
  umask(mask);
#endif /* WIN32 */

  g_free(file_name);
  if (!filep) {
    fprintf(stderr, _("Could not write client profile file\n"));
    return -1;
  }

  int err = 0;
  if (otrng_failed(
          otrng_global_state_prekey_profile_write_to(otrng_state, filep))) {
    err = -1;
  }
  fclose(filep);

  return err;
}

/* Generate a private key for the given accountname/protocol */
void otrng_plugin_create_privkey_v3(const PurpleAccount *account) {
  OtrgDialogWaitHandle waithandle;
  const char *accountname = purple_account_get_username(account);
  const char *protocol = purple_account_get_protocol_id(account);

  waithandle = otrng_dialog_private_key_wait_start(accountname, protocol);

  // TODO: check the return value
  otrng_plugin_write_privkey_v3_FILEp((PurpleAccount *)account);
  otrng_ui_update_fingerprint();

  /* Mark the dialog as done. */
  otrng_dialog_private_key_wait_done(waithandle);
}

void otrng_plugin_write_expired_client_profile(const PurpleAccount *account) {
  if (otrng_succeeded(otrng_global_state_generate_client_profile(
          otrng_state, purple_account_to_client_id(account)))) {
    // TODO: check the return error
    otrng_plugin_write_expired_client_profile_FILEp();
  }
}

void otrng_plugin_write_expired_prekey_profile(const PurpleAccount *account) {
  if (otrng_succeeded(otrng_global_state_generate_prekey_profile(
          otrng_state, purple_account_to_client_id(account)))) {
    // TODO: check the return error
    otrng_plugin_write_expired_prekey_profile_FILEp();
  }
}

/* Generate a instance tag for the given accountname/protocol */
void otrng_plugin_create_instag(const PurpleAccount *account) {
  FILE *instagf;

  gchar *instagfile =
      g_build_filename(purple_user_dir(), INSTAG_FILE_NAME, NULL);
  if (!instagfile) {
    fprintf(stderr, _("Out of memory building filenames!\n"));
    return;
  }
  instagf = g_fopen(instagfile, "w+b");
  g_free(instagfile);
  if (!instagf) {
    fprintf(stderr, _("Could not write instange tag file\n"));
    return;
  }

  /* Generate the instag */
  // TODO: check the return value
  otrng_global_state_instag_generate_into(
      otrng_state, purple_account_to_client_id(account), instagf);

  fclose(instagf);
}

static void create_privkey_cb(void *opdata, const char *account_name,
                              const char *protocol_name) {
  otrng_plugin_create_privkey_v3(opdata);
}

static void create_instag_cb(const otrng_client_id_s opdata) {
  otrng_plugin_create_instag(client_id_to_purple_account(opdata));
}

static int is_logged_in_cb(void *opdata, const char *accountname,
                           const char *protocol, const char *recipient) {
  PurpleAccount *account;
  PurpleBuddy *buddy;

  account = purple_accounts_find(accountname, protocol);
  if (!account) {
    return -1;
  }

  buddy = purple_find_buddy(account, recipient);
  if (!buddy) {
    return -1;
  }

  return (PURPLE_BUDDY_IS_ONLINE(buddy));
}

static void inject_message_cb(void *opdata, const char *accountname,
                              const char *protocol, const char *recipient,
                              const char *message) {
  PurpleAccount *account = purple_accounts_find(accountname, protocol);
  if (!account) {
    PurplePlugin *p = purple_find_prpl(protocol);
    char *msg =
        g_strdup_printf(_("Unknown account %s (%s)."), accountname,
                        (p && p->info->name) ? p->info->name : _("Unknown"));
    otrng_dialog_notify_error(accountname, protocol, recipient,
                              _("Unknown account"), msg, NULL);
    g_free(msg);
    return;
  }
  otrng_plugin_inject_message(account, recipient, message);
}

static void update_context_list_cb(void *opdata) { otrng_ui_update_keylist(); }

static void confirm_fingerprint_cb(void *opdata, OtrlUserState us,
                                   const char *accountname,
                                   const char *protocol, const char *username,
                                   unsigned char fingerprint[20]) {
  otrng_dialog_unknown_fingerprint(us, accountname, protocol, username,
                                   fingerprint);
}

static void write_fingerprints_cb(void *opdata) {
  otrng_plugin_write_fingerprints();
  otrng_ui_update_keylist();
  otrng_dialog_resensitize_all();
}

static void still_secure_cb(void *opdata, ConnContext *context, int is_reply) {
  if (is_reply == 0) {
    otrng_dialog_stillconnected(context);
  }
}

static int max_message_size_cb(void *opdata, ConnContext *context) {
  void *lookup_result =
      g_hash_table_lookup(otrng_max_message_size_table, context->protocol);
  if (!lookup_result) {
    return 0;
  }
  return *((int *)lookup_result);
}

static const char *otr_error_message_cb(void *opdata, ConnContext *context,
                                        OtrlErrorCode err_code) {
  char *err_msg = NULL;
  switch (err_code) {
  case OTRL_ERRCODE_NONE:
    break;
  case OTRL_ERRCODE_ENCRYPTION_ERROR:
    err_msg = g_strdup(_("Error occurred encrypting message."));
    break;
  case OTRL_ERRCODE_MSG_NOT_IN_PRIVATE:
    if (context) {
      err_msg = g_strdup_printf(_("You sent encrypted data to %s, who"
                                  " wasn't expecting it."),
                                context->accountname);
    }
    break;
  case OTRL_ERRCODE_MSG_UNREADABLE:
    err_msg = g_strdup(_("You transmitted an unreadable encrypted message."));
    break;
  case OTRL_ERRCODE_MSG_MALFORMED:
    err_msg = g_strdup(_("You transmitted a malformed data message."));
    break;
  }
  return err_msg;
}

static void otr_error_message_free_cb(void *opdata, const char *err_msg) {
  if (err_msg) {
    g_free((char *)err_msg);
  }
}

static const char *resent_msg_prefix_cb(void *opdata, ConnContext *context) {
  return g_strdup(_("[resent]"));
}

static void resent_msg_prefix_free_cb(void *opdata, const char *prefix) {
  if (prefix) {
    g_free((char *)prefix);
  }
}

/* Treat this event like other incoming messages. This allows message
 * notification events to get properly triggered. */
static void emit_msg_received(ConnContext *context, const char *message) {
  PurpleConversation *conv = otrng_plugin_userinfo_to_conv(
      context->accountname, context->protocol, context->username, 1);
  PurpleMessageFlags flags =
      PURPLE_MESSAGE_RECV | PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NOTIFY;
  PurpleAccount *account = purple_conversation_get_account(conv);

  purple_signal_emit(purple_conversations_get_handle(), "received-im-msg",
                     account, context->username, message, conv, flags);
}

static void handle_msg_event_cb(void *opdata, OtrlMessageEvent msg_event,
                                ConnContext *context, const char *message,
                                gcry_error_t err) {
  PurpleConversation *conv = NULL;
  gchar *buf;
  OtrlMessageEvent *last_msg_event;

  if (!context) {
    return;
  }

  conv = otrng_plugin_context_to_conv(context, 1);
  last_msg_event = g_hash_table_lookup(conv->data, "otr-last_msg_event");

  switch (msg_event) {
  case OTRL_MSGEVENT_NONE:
    break;
  case OTRL_MSGEVENT_ENCRYPTION_REQUIRED:
    buf = g_strdup_printf(_("You attempted to send an "
                            "unencrypted message to %s"),
                          context->username);
    display_otr_message_or_notify(
        opdata, context->accountname, context->protocol, context->username,
        _("Attempting to"
          " start a private conversation..."),
        1, OTRL_NOTIFY_WARNING, _("OTR Policy Violation"), buf,
        _("Unencrypted messages to this recipient are "
          "not allowed.  Attempting to start a private "
          "conversation.\n\nYour message will be "
          "retransmitted when the private conversation "
          "starts."));
    g_free(buf);
    break;
  case OTRL_MSGEVENT_ENCRYPTION_ERROR:
    display_otr_message_or_notify(
        opdata, context->accountname, context->protocol, context->username,
        _("An error occurred "
          "when encrypting your message.  The message was not sent."),
        1, OTRL_NOTIFY_ERROR, _("Error encrypting message"),
        _("An error occurred when encrypting your message"),
        _("The message was not sent."));
    break;
  case OTRL_MSGEVENT_CONNECTION_ENDED:
    buf = g_strdup_printf(_("%s has already closed his/her private "
                            "connection to you"),
                          context->username);
    display_otr_message_or_notify(
        opdata, context->accountname, context->protocol, context->username,
        _("Your message "
          "was not sent.  Either end your private conversation, "
          "or restart it."),
        1, OTRL_NOTIFY_ERROR, _("Private connection closed"), buf,
        _("Your message was not sent.  Either close your "
          "private connection to him, or refresh it."));
    g_free(buf);
    break;
  case OTRL_MSGEVENT_SETUP_ERROR:
    if (!err) {
      err = GPG_ERR_INV_VALUE;
    }
    switch (gcry_err_code(err)) {
    case GPG_ERR_INV_VALUE:
      buf = g_strdup(_("Error setting up private "
                       "conversation: Malformed message received"));
      break;
    default:
      buf = g_strdup_printf(_("Error setting up private "
                              "conversation: %s"),
                            gcry_strerror(err));
      break;
    }

    display_otr_message_or_notify(opdata, context->accountname,
                                  context->protocol, context->username, buf, 1,
                                  OTRL_NOTIFY_ERROR, _("OTR Error"), buf, NULL);
    g_free(buf);
    break;
  case OTRL_MSGEVENT_MSG_REFLECTED:
    display_otr_message_or_notify(
        opdata, context->accountname, context->protocol, context->username,
        _("We are receiving our own OTR messages.  "
          "You are either trying to talk to yourself, "
          "or someone is reflecting your messages back "
          "at you."),
        1, OTRL_NOTIFY_ERROR, _("OTR Error"),
        _("We are receiving our own OTR messages."),
        _("You are either trying to talk to yourself, "
          "or someone is reflecting your messages back "
          "at you."));
    break;
  case OTRL_MSGEVENT_MSG_RESENT:
    buf = g_strdup_printf(_("<b>The last message to %s was resent."
                            "</b>"),
                          context->username);
    display_otr_message_or_notify(
        opdata, context->accountname, context->protocol, context->username, buf,
        1, OTRL_NOTIFY_INFO, _("Message resent"), buf, NULL);
    g_free(buf);
    break;
  case OTRL_MSGEVENT_RCVDMSG_NOT_IN_PRIVATE:
    buf = g_strdup_printf(
        _("<b>The encrypted message received from "
          "%s is unreadable, as you are not currently communicating "
          "privately.</b>"),
        context->username);
    display_otr_message_or_notify(
        opdata, context->accountname, context->protocol, context->username, buf,
        1, OTRL_NOTIFY_INFO, _("Unreadable message"), buf, NULL);
    g_free(buf);
    break;
  case OTRL_MSGEVENT_RCVDMSG_UNREADABLE:
    buf = g_strdup_printf(_("We received an unreadable "
                            "encrypted message from %s."),
                          context->username);
    display_otr_message_or_notify(opdata, context->accountname,
                                  context->protocol, context->username, buf, 1,
                                  OTRL_NOTIFY_ERROR, _("OTR Error"), buf, NULL);
    g_free(buf);
    break;
  case OTRL_MSGEVENT_RCVDMSG_MALFORMED:
    buf = g_strdup_printf(_("We received a malformed data "
                            "message from %s."),
                          context->username);
    display_otr_message_or_notify(opdata, context->accountname,
                                  context->protocol, context->username, buf, 1,
                                  OTRL_NOTIFY_ERROR, _("OTR Error"), buf, NULL);
    g_free(buf);
    break;
  case OTRL_MSGEVENT_LOG_HEARTBEAT_RCVD:
    buf =
        g_strdup_printf(_("Heartbeat received from %s.\n"), context->username);
    log_message(opdata, buf);
    g_free(buf);
    break;
  case OTRL_MSGEVENT_LOG_HEARTBEAT_SENT:
    buf = g_strdup_printf(_("Heartbeat sent to %s.\n"), context->username);
    log_message(opdata, buf);
    g_free(buf);
    break;
  case OTRL_MSGEVENT_RCVDMSG_GENERAL_ERR:
    display_otr_message_or_notify(
        opdata, context->accountname, context->protocol, context->username,
        message, 1, OTRL_NOTIFY_ERROR, _("OTR Error"), message, NULL);
    break;
  case OTRL_MSGEVENT_RCVDMSG_UNENCRYPTED:
    buf =
        g_strdup_printf(_("<b>The following message received "
                          "from %s was <i>not</i> encrypted: [</b>%s<b>]</b>"),
                        context->username, message);
    display_otr_message_or_notify(
        opdata, context->accountname, context->protocol, context->username, buf,
        1, OTRL_NOTIFY_INFO, _("Received unencrypted message"), buf, NULL);
    emit_msg_received(context, buf);
    g_free(buf);
    break;
  case OTRL_MSGEVENT_RCVDMSG_UNRECOGNIZED:
    buf = g_strdup_printf(_("Unrecognized OTR message received "
                            "from %s.\n"),
                          context->username);
    log_message(opdata, buf);
    g_free(buf);
    break;
  case OTRL_MSGEVENT_RCVDMSG_FOR_OTHER_INSTANCE:
    if (*last_msg_event == msg_event) {
      break;
    }
    buf = g_strdup_printf(
        _("%s has sent a message intended for a "
          "different session. If you are logged in multiple times, "
          "another session may have received the message."),
        context->username);
    display_otr_message_or_notify(opdata, context->accountname,
                                  context->protocol, context->username, buf, 1,
                                  OTRL_NOTIFY_INFO,
                                  _("Received message for a different "
                                    "session"),
                                  buf, NULL);
    g_free(buf);
    break;
  }

  *last_msg_event = msg_event;
}

#ifdef DUMP_RECEIVED_SYMKEY
static void dump_data(const unsigned char *d, size_t l) {
  size_t i;
  for (i = 0; i < l; ++i)
    printf("%02x", d[i]);
}

static void received_symkey_cb(void *opdata, ConnContext *context,
                               unsigned int use, const unsigned char *usedata,
                               size_t usedatalen, const unsigned char *symkey) {
  printf("Received symkey use: %08x\nKey: ", use);
  dump_data(symkey, OTRL_EXTRAKEY_BYTES);
  printf("\nUsedata: ");
  dump_data(usedata, usedatalen);
  printf("\n\n");
}
#endif

static guint otrng_plugin_timerid = 0;

/* Called by the glib main loop, as set up by stop_start_timer */
static gboolean timer_fired_cb(gpointer data);

/* Stop the timer, if it's currently running.  If interval > 0, start it
 * to periodically fire every interval seconds. */
static void stop_start_timer(unsigned int interval) {
  if (otrng_plugin_timerid) {
    g_source_remove(otrng_plugin_timerid);
    otrng_plugin_timerid = 0;
  }
  if (interval > 0) {
    otrng_plugin_timerid =
        g_timeout_add_seconds(interval, timer_fired_cb, NULL);
  }
}

/* Called by libotr */
static void timer_control_cb(void *opdata, unsigned int interval) {
  stop_start_timer(interval);
}

static OtrlMessageAppOps ui_ops = {policy_cb,
                                   create_privkey_cb, // create_privkey_cb,
                                   is_logged_in_cb,
                                   inject_message_cb,
                                   update_context_list_cb,
                                   confirm_fingerprint_cb,
                                   write_fingerprints_cb,
                                   NULL, // gone_secure_cb
                                   NULL, // gone_insecure_cb
                                   still_secure_cb,
                                   max_message_size_cb,
                                   NULL, /* account_name */
                                   NULL, /* account_name_free */
#ifdef DUMP_RECEIVED_SYMKEY
                                   received_symkey_cb,
#else
                                   NULL, /* received_symkey */
#endif
                                   otr_error_message_cb,
                                   otr_error_message_free_cb,
                                   resent_msg_prefix_cb,
                                   resent_msg_prefix_free_cb,
                                   NULL, // handle_smp_event_cb,
                                   handle_msg_event_cb,
                                   NULL, // create_instag_cb
                                   NULL, /* convert_data */
                                   NULL, /* convert_data_free */
                                   timer_control_cb};

/* Called by the glib main loop, as set up by stop_start_timer */
static gboolean timer_fired_cb(gpointer data) {
  // TODO: There should be an equivalent for this
  otrl_message_poll(otrng_state->user_state_v3, &ui_ops, NULL);
  return TRUE;
}

typedef struct {
  char *username;
  char **message;
} prekey_client_offline_message_ctx_s;

static void get_prekey_client_for_sending_offline_message(
    PurpleAccount *account, otrng_client_s *client,
    otrng_prekey_client_s *prekey_client, void *xctx) {
  prekey_client_offline_message_ctx_s *c = xctx;

  // Try to send an offline message
  otrng_debug_fprintf(stderr, "Should try to send an offline message to %s\n",
                      c->username);

  // 1. get prekey ensemble for this person
  if (!prekey_client) {
    return;
  }

  otrng_plugin_offline_message_ctx *ctx =
      malloc(sizeof(otrng_plugin_offline_message_ctx));
  ctx->account = account;
  ctx->message = g_strdup(*c->message);
  ctx->recipient = c->username;

  // TODO: This should probably be passed as a parameter to
  // otrng_prekey_client_retrieve_prekeys
  prekey_client->callbacks->ctx = ctx;

  // TODO: here we should NOT user the server identity from the prekey_client
  //    since it will only work if we're on the same server
  char *send_to_prekey_server =
      otrng_prekey_client_retrieve_prekeys(c->username, "4", prekey_client);
  otrng_plugin_inject_message(account, prekey_client->server_identity,
                              send_to_prekey_server);
  free(send_to_prekey_server);
}

int otrng_plugin_buddy_is_offline(PurpleAccount *account, PurpleBuddy *buddy) {
  return buddy && purple_account_supports_offline_message(account, buddy) &&
         !PURPLE_BUDDY_IS_ONLINE(buddy);
}

static void send_offline_message(char **message, const char *username,
                                 PurpleAccount *account) {
  prekey_client_offline_message_ctx_s *ctx =
      malloc(sizeof(prekey_client_offline_message_ctx_s));
  if (!ctx) {
    return;
  }
  ctx->username = g_strdup(purple_normalize(account, username));
  ctx->message = message;

  otrng_plugin_get_prekey_client(
      account, get_prekey_client_for_sending_offline_message, ctx);
  return;
}

void otrng_plugin_send_non_interactive_auth(const char *username,
                                            PurpleAccount *account) {
  char **message = malloc(sizeof(char *));
  if (!message) {
    return;
  }

  *message = "\0";
  send_offline_message(message, username, account);
  return;
}

static void process_sending_im(PurpleAccount *account, char *who,
                               char **message, void *ctx) {
  char *newmessage = NULL;
  char *username = NULL;

  // const char *accountname = purple_account_get_username(account);
  // const char *protocol = purple_account_get_protocol_id(account);
  // PurpleConversation * conv = NULL;
  // otrl_instag_t instance;

  if (!who || !message || !*message) {
    return;
  }

  // conv = otrng_plugin_userinfo_to_conv(accountname, protocol, username, 1);
  // instance = otrng_plugin_conv_to_selected_instag(conv, OTRL_INSTAG_BEST);

  username = g_strdup(purple_normalize(account, who));

  otrng_client_s *client = purple_account_to_otrng_client(account);
  otrng_client_ensure_correct_state(client);
  trigger_potential_publishing(client);

  otrng_conversation_s *otr_conv =
      otrng_client_get_conversation(0, username, client);
  PurpleBuddy *buddy = purple_find_buddy(account, username);

  if (otrng_plugin_buddy_is_offline(account, buddy) &&
      !otrng_conversation_is_encrypted(otr_conv)) {
    send_offline_message(message, username, account);
    return;
  }

  otrng_result result =
      otrng_client_send(&newmessage, *message, username, client);

  // TODO: this message should be stored for retransmission
  // TODO: this will never be true - we need to change otrng_client_send to
  // accomodate this
  /* if (result == OTRNG_CLIENT_RESULT_ERROR_NOT_ENCRYPTED) { */
  /*   return; */
  /* } */

  // TODO: if require encription
  // if (err == ???) {
  //    /* Do not send out plain text */
  //    char *ourm = g_strdup("");
  //    free(*message);
  //    *message = ourm;
  //}

  if (otrng_succeeded(result)) {
    free(*message);
    *message = g_strdup(newmessage);
  }

  // TODO: This is probably because libotr use a different mechanism to allocate
  // memory securely
  otrl_message_free(newmessage);
  g_free(username);
}

/* Abort the SMP protocol.  Used when malformed or unexpected messages
 * are received. */
void otrng_plugin_abort_smp(const otrng_plugin_conversation *conv) {
  // TODO: create and inject abort SMP message.
  // otrng_client_adapter_smp_abort(&tosend, conv->peer, question, secret,
  // secretlen, client);
}

// TODO: REMOVE
otrng_client_s *
otrng_plugin_conversation_to_client(const otrng_plugin_conversation *conv) {
  return get_otrng_client(conv->protocol, conv->account);
}

otrng_plugin_conversation *otrng_plugin_conversation_new(const char *account,
                                                         const char *protocol,
                                                         const char *peer) {
  otrng_plugin_conversation *ret = malloc(sizeof(otrng_plugin_conversation));
  if (!ret) {
    return ret;
  }

  ret->account = g_strdup(account);
  ret->protocol = g_strdup(protocol);
  ret->peer = g_strdup(peer);
  ret->their_instance_tag = 0;
  ret->our_instance_tag = 0;

  return ret;
}

otrng_plugin_conversation *
otrng_plugin_conversation_copy(const otrng_plugin_conversation *conv) {
  otrng_plugin_conversation *ret =
      otrng_plugin_conversation_new(conv->account, conv->protocol, conv->peer);
  if (!ret) {
    return ret;
  }

  ret->their_instance_tag = conv->their_instance_tag;
  ret->our_instance_tag = conv->our_instance_tag;

  return ret;
}

otrng_plugin_conversation *
purple_conversation_to_plugin_conversation(const PurpleConversation *conv) {
  PurpleAccount *account = purple_conversation_get_account(conv);

  account = purple_conversation_get_account(conv);

  char *accountname =
      g_strdup(purple_normalize(account, purple_account_get_username(account)));
  const char *protocol = purple_account_get_protocol_id(account);
  char *peer =
      g_strdup(purple_normalize(account, purple_conversation_get_name(conv)));

  otrng_plugin_conversation *result =
      otrng_plugin_conversation_new(accountname, protocol, peer);
  free(peer);
  free(accountname);
  return result;
}

void otrng_plugin_conversation_free(otrng_plugin_conversation *conv) {
  if (!conv) {
    return;
  }

  g_free(conv->account);
  conv->account = NULL;

  g_free(conv->protocol);
  conv->protocol = NULL;

  g_free(conv->peer);
  conv->peer = NULL;

  free(conv);
}

/* Start the Socialist Millionaires' Protocol over the current connection,
 * using the given initial secret, and optionally a question to pass to
 * the buddy. */
void otrng_plugin_start_smp(otrng_plugin_conversation *conv,
                            const unsigned char *question, const size_t q_len,
                            const unsigned char *secret, size_t secretlen) {
  otrng_client_s *client = otrng_plugin_conversation_to_client(conv);
  if (!client) {
    return;
  }

  char *tosend = NULL;
  if (otrng_failed(otrng_client_smp_start(&tosend, conv->peer, question, q_len,
                                          secret, secretlen, client))) {
    return; // ERROR?
  }

  PurpleConversation *purp_conv = NULL;
  PurpleAccount *account = NULL;
  purp_conv = otrng_plugin_userinfo_to_conv(conv->account, conv->protocol,
                                            conv->peer, 1);
  account = purple_conversation_get_account(purp_conv);
  otrng_plugin_inject_message(account, conv->peer, tosend);
  free(tosend);
}

/* Continue the Socialist Millionaires' Protocol over the current connection,
 * using the given initial secret (ie finish step 2). */
void otrng_plugin_continue_smp(otrng_plugin_conversation *conv,
                               const unsigned char *secret, size_t secretlen) {
  otrng_client_s *client = otrng_plugin_conversation_to_client(conv);
  if (!client) {
    return;
  }

  char *tosend = NULL;
  if (otrng_failed(otrng_client_smp_respond(&tosend, conv->peer, secret,
                                            secretlen, client))) {
    return; // ERROR?
  }

  PurpleConversation *purp_conv = NULL;
  PurpleAccount *account = NULL;
  purp_conv = otrng_plugin_userinfo_to_conv(conv->account, conv->protocol,
                                            conv->peer, 1);
  account = purple_conversation_get_account(purp_conv);
  otrng_plugin_inject_message(account, conv->peer, tosend);
  free(tosend);
}

#define OTRG_PLUGIN_DEFAULT_QUERY "?OTRv34?"

void otrng_plugin_send_default_query(otrng_plugin_conversation *conv) {
  PurpleConversation *purp_conv = NULL;
  PurpleAccount *account = NULL;
  char *msg;
  char *username;

  purp_conv = otrng_plugin_userinfo_to_conv(conv->account, conv->protocol,
                                            conv->peer, 1);

  // TODO: change this later, but it is so, so it does compile
  account = purple_conversation_get_account(purp_conv);
  username = g_strdup(
      purple_normalize(account, purple_conversation_get_name(purp_conv)));
  OtrgUiPrefs prefs;
  otrng_ui_get_prefs(&prefs, account, username);
  free(username);

  otrng_client_s *client = get_otrng_client(conv->protocol, conv->account);
  if (!client) {
    return;
  }

  // TODO: Use policy?
  // prefs.policy
  msg = otrng_client_query_message(conv->peer, "", client);

  otrng_plugin_inject_message(account, conv->peer,
                              msg ? msg : OTRG_PLUGIN_DEFAULT_QUERY);
  free(msg);
}

/* Send the default OTR Query message to the correspondent of the given
 * conversation. */
void otrng_plugin_send_default_query_conv(PurpleConversation *conv) {
  PurpleAccount *account = NULL;
  char *peer = NULL;
  char *msg = NULL;
  OtrgUiPrefs prefs;

  account = purple_conversation_get_account(conv);
  // accountname = purple_account_get_username(account);

  otrng_client_s *client = purple_account_to_otrng_client(account);

  peer =
      g_strdup(purple_normalize(account, purple_conversation_get_name(conv)));
  otrng_ui_get_prefs(&prefs, account, peer);

  // TODO: Use policy?
  // prefs.policy
  msg = otrng_client_query_message(peer, "", client);
  otrng_plugin_inject_message(account, peer,
                              msg ? msg : OTRG_PLUGIN_DEFAULT_QUERY);
  free(peer);
  free(msg);
}

static gboolean process_receiving_im(PurpleAccount *account, char **who,
                                     char **message, PurpleConversation *conv,
                                     PurpleMessageFlags *flags) {
  char *username = NULL;
  char *tosend = NULL;
  char *todisplay = NULL;
  otrng_bool should_ignore = otrng_false;

  // OtrlTLV *tlvs = NULL;
  // OtrlTLV *tlv = NULL;
  // const char *accountname;
  // const char *protocol;

  if (!who || !*who || !message || !*message) {
    return 0;
  }

  username = g_strdup(purple_normalize(account, *who));

  otrng_client_s *client = purple_account_to_otrng_client(account);

  otrng_client_receive(&tosend, &todisplay, *message, username, client,
                       &should_ignore);

  // TODO: client might optionally pass a warning here
  // TODO: this will likely not work correctly at all, since otrng_result
  // doesn't have that kind of result
  /* if (res == OTRNG_CLIENT_RESULT_ERROR_NOT_ENCRYPTED) { */
  /*   // TODO: Needs to free tosend AND todisplay */
  /*   return 1; */
  /* } */

  if (tosend) {
    // TODO: Should this send to the original who or to the normalized who?
    otrng_plugin_inject_message(account, username, tosend);
    free(tosend);
  }

  if (todisplay) {
    free(*message);
    *message = g_strdup(todisplay);
  } else {
    /* If we're supposed to ignore this incoming message (because it's a
     * protocol message), set it to NULL, so that other plugins that
     * catch receiving-im-msg don't return 0, and cause it to be
     * displayed anyway. */
    free(*message);
    *message = NULL;
  }

  free(username);
  return should_ignore == otrng_true;
}

// TODO: Remove me
/* Find the ConnContext appropriate to a given PurpleConversation. */
ConnContext *otrng_plugin_conv_to_context(PurpleConversation *conv,
                                          otrl_instag_t their_instance,
                                          int force_create) {
  PurpleAccount *account;
  const char *username;
  const char *accountname, *proto;
  ConnContext *context;

  if (!conv) {
    return NULL;
  }

  account = purple_conversation_get_account(conv);
  accountname = purple_account_get_username(account);
  proto = purple_account_get_protocol_id(account);
  username = purple_conversation_get_name(conv);

  context =
      otrl_context_find(otrng_state->user_state_v3, username, accountname,
                        proto, their_instance, force_create, NULL, NULL, NULL);

  return context;
}

/* Given a PurpleConversation, return the selected instag */
otrl_instag_t otrng_plugin_conv_to_selected_instag(PurpleConversation *conv,
                                                   otrl_instag_t default_val) {
  otrl_instag_t *selected_instance;

  if (!conv || !conv->data) {
    return default_val;
  }

  selected_instance = purple_conversation_get_data(conv, "otr-ui_selected_ctx");

  if (!selected_instance) {
    return default_val;
  }

  return *selected_instance;
}

/* Given a PurpleConversation, return the selected ConnContext */
ConnContext *otrng_plugin_conv_to_selected_context(PurpleConversation *conv,
                                                   int force_create) {
  otrl_instag_t selected_instance;

  selected_instance =
      otrng_plugin_conv_to_selected_instag(conv, OTRL_INSTAG_BEST);

  return otrng_plugin_conv_to_context(conv, selected_instance, force_create);
}

static void process_conv_create(PurpleConversation *conv) {
  otrl_instag_t *selected_instance;
  OtrlMessageEvent *msg_event;
  if (!conv) {
    return;
  }

  /* If this malloc fails (or the other below), trouble will be
   * unavoidable. */
  selected_instance = g_malloc(sizeof(otrl_instag_t));
  *selected_instance = OTRL_INSTAG_BEST;
  purple_conversation_set_data(conv, "otr-ui_selected_ctx",
                               (gpointer)selected_instance);

  msg_event = g_malloc(sizeof(OtrlMessageEvent));
  *msg_event = OTRL_MSGEVENT_NONE;
  purple_conversation_set_data(conv, "otr-last_msg_event", (gpointer)msg_event);

  otrng_dialog_new_conv(conv);
}

/* Wrapper around process_conv_create for callback purposes */
static void process_conv_create_cb(PurpleConversation *conv, void *data) {
  process_conv_create(conv);
}

static void process_conv_updated(PurpleConversation *conv,
                                 PurpleConvUpdateType type, void *data) {
  /* See if someone's trying to turn logging on for this conversation,
   * and we don't want them to. */
  if (type == PURPLE_CONV_UPDATE_LOGGING) {
    ConnContext *context;
    OtrgUiPrefs prefs;
    PurpleAccount *account = purple_conversation_get_account(conv);
    otrng_ui_get_prefs(&prefs, account, purple_conversation_get_name(conv));

    context = otrng_plugin_conv_to_selected_context(conv, 0);
    if (context && prefs.avoid_logging_otr &&
        context->msgstate == OTRL_MSGSTATE_ENCRYPTED && conv->logging == TRUE) {
      purple_conversation_set_logging(conv, FALSE);
    }
  }
}

static void process_conv_destroyed(PurpleConversation *conv) {
  otrl_instag_t *selected_instance =
      purple_conversation_get_data(conv, "otr-ui_selected_ctx");
  OtrlMessageEvent *msg_event =
      purple_conversation_get_data(conv, "otr-last_msg_event");

  if (selected_instance) {
    g_free(selected_instance);
  }

  if (msg_event) {
    g_free(msg_event);
  }

  g_hash_table_remove(conv->data, "otr-ui_selected_ctx");
  g_hash_table_remove(conv->data, "otr-last_msg_event");
}

static void process_connection_change(PurpleConnection *conn, void *data) {
  /* If we log in or out of a connection, make sure all of the OTR
   * buttons are in the appropriate sensitive/insensitive state. */
  otrng_dialog_resensitize_all();
}

static void otr_options_cb(PurpleBlistNode *node, gpointer user_data) {
  /* We've already checked PURPLE_BLIST_NODE_IS_BUDDY(node) */
  PurpleBuddy *buddy = (PurpleBuddy *)node;

  /* Modify the settings for this buddy */
  otrng_ui_config_buddy(buddy);
}

static void supply_extended_menu(PurpleBlistNode *node, GList **menu) {
  PurpleMenuAction *act;
  PurpleBuddy *buddy;
  PurpleAccount *acct;
  const char *proto;

  if (!PURPLE_BLIST_NODE_IS_BUDDY(node)) {
    return;
  }

  /* Extract the account, and then the protocol, for this buddy */
  buddy = (PurpleBuddy *)node;
  acct = buddy->account;
  if (acct == NULL) {
    return;
  }
  proto = purple_account_get_protocol_id(acct);
  if (!otrng_plugin_proto_supports_otr(proto)) {
    return;
  }

  act = purple_menu_action_new(_("OTR Settings"),
                               (PurpleCallback)otr_options_cb, NULL, NULL);
  *menu = g_list_append(*menu, act);
}

/* Disconnect all context instances, sending a notice to the other side, if
 * appropriate. */
void otrng_plugin_disconnect_all_instances(ConnContext *context) {
  // TODO: There should be an equivalent for this
  otrl_message_disconnect_all_instances(otrng_state->user_state_v3, &ui_ops,
                                        NULL, context->accountname,
                                        context->protocol, context->username);
}

/* Disconnect a context, sending a notice to the other side, if
 * appropriate. */
void otrng_plugin_disconnect(otrng_plugin_conversation *conv) {
  char *msg = NULL;
  PurpleConversation *purp_conv = NULL;
  PurpleAccount *account = NULL;
  otrng_client_s *client = NULL;

  if (!conv) {
    return;
  }

  client = get_otrng_client(conv->protocol, conv->account);
  if (!client) {
    return;
  }

  purp_conv = otrng_plugin_userinfo_to_conv(conv->account, conv->protocol,
                                            conv->peer, 1);
  account = purple_conversation_get_account(purp_conv);

  if (otrng_succeeded(otrng_client_disconnect(&msg, conv->peer, client))) {
    otrng_plugin_inject_message(account, conv->peer, msg);
  }

  free(msg);
}

static void add_fingerprint_to_file(gpointer key, gpointer value,
                                    gpointer user_data) {
  otrng_plugin_fingerprint *fp = value;
  FILE *storef = user_data;

  fprintf(storef, "%s\t%s\t%s\t", fp->username, fp->account, fp->protocol);
  fprintf(storef, "%s\t%s\n", fp->fp, fp->trusted ? "trusted" : "");
}

void otrng_plugin_write_fingerprints_v4(void) {
#ifndef WIN32
  mode_t mask;
#endif /* WIN32 */
  FILE *storef;
  gchar *storefile =
      g_build_filename(purple_user_dir(), STORE_FILE_NAME_v4, NULL);
#ifndef WIN32
  mask = umask(0077);
#endif /* WIN32 */
  storef = g_fopen(storefile, "wb");
#ifndef WIN32
  umask(mask);
#endif /* WIN32 */
  g_free(storefile);
  if (!storef) {
    return;
  }

  g_hash_table_foreach(otrng_fingerprints_table, add_fingerprint_to_file,
                       storef);

  fclose(storef);
}

/* Write the fingerprints to disk. */
void otrng_plugin_write_fingerprints(void) {
  // TODO: write otrv3 fingerprints
  otrng_plugin_write_fingerprints_v4();
}

void otrng_plugin_read_fingerprints_FILEp(FILE *storef) {
  char storeline[1000];
  size_t maxsize = sizeof(storeline);

  if (!storef) {
    return;
  }

  while (fgets(storeline, maxsize, storef)) {
    char *username;
    char *accountname;
    char *protocol;
    char *fp_human;
    char *trust;
    char *tab;
    char *eol;
    otrng_plugin_fingerprint *fng;

    /* Parse the line, which should be of the form:
     *    username\taccountname\tprotocol\t40_hex_nybbles\n          */
    username = storeline;
    tab = strchr(username, '\t');
    if (!tab) {
      continue;
    }
    *tab = '\0';

    accountname = tab + 1;
    tab = strchr(accountname, '\t');
    if (!tab) {
      continue;
    }
    *tab = '\0';

    protocol = tab + 1;
    tab = strchr(protocol, '\t');
    if (!tab) {
      continue;
    }
    *tab = '\0';

    fp_human = tab + 1;
    tab = strchr(fp_human, '\t');
    if (!tab) {
      eol = strchr(fp_human, '\r');
      if (!eol) {
        eol = strchr(fp_human, '\n');
      }
      if (!eol) {
        continue;
      }
      *eol = '\0';
      trust = NULL;
    } else {
      *tab = '\0';
      trust = tab + 1;
      eol = strchr(trust, '\r');
      if (!eol) {
        eol = strchr(trust, '\n');
      }
      if (!eol) {
        continue;
      }
      *eol = '\0';
    }

    if (strlen(fp_human) != OTRNG_FPRINT_HUMAN_LEN - 1) {
      continue;
    }

    fng = otrng_plugin_fingerprint_get(fp_human);
    if (!fng) {
      fng = otrng_plugin_fingerprint_new(fp_human, protocol, accountname,
                                         username);
    }

    if (!fng) {
      continue;
    }

    fng->trusted = strlen(trust) ? 1 : 0;
  }
}

/* Find the PurpleConversation appropriate to the given userinfo.  If
 * one doesn't yet exist, create it if force_create is true. */
PurpleConversation *otrng_plugin_userinfo_to_conv(const char *accountname,
                                                  const char *protocol,
                                                  const char *username,
                                                  int force_create) {
  PurpleAccount *account;
  PurpleConversation *conv;

  account = purple_accounts_find(accountname, protocol);
  if (account == NULL) {
    return NULL;
  }

  conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, username,
                                               account);
  if (conv == NULL && force_create) {
    conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, account, username);
  }

  return conv;
}

/* Find the PurpleConversation appropriate to the given ConnContext.  If
 * one doesn't yet exist, create it if force_create is true. */
PurpleConversation *otrng_plugin_context_to_conv(ConnContext *context,
                                                 int force_create) {
  return otrng_plugin_userinfo_to_conv(context->accountname, context->protocol,
                                       context->username, force_create);
}

TrustLevel
otrng_plugin_conversation_to_trust(const otrng_plugin_conversation *conv) {
  TrustLevel level = TRUST_NOT_PRIVATE;
  if (!conv) {
    return level;
  }

  otrng_client_s *client = get_otrng_client(conv->protocol, conv->account);
  if (!client) {
    return level;
  }

  otrng_conversation_s *otr_conv =
      otrng_client_get_conversation(1, conv->peer, client);

  if (!otr_conv) {
    return level;
  }

  // Use OTR3 if available
  if (otr_conv->conn->running_version == 3) {
    return otrng_plugin_context_to_trust(otr_conv->conn->v3_conn->ctx);
  }

  otrng_plugin_fingerprint *fp =
      otrng_plugin_fingerprint_get_active(conv->peer);

  if (otrng_conversation_is_encrypted(otr_conv)) {
    if (fp->trusted) {
      level = TRUST_PRIVATE;
    } else {
      level = TRUST_UNVERIFIED;
    }
  } else if (otrng_conversation_is_finished(otr_conv)) {
    level = TRUST_FINISHED;
  }

  return level;
}

/* What level of trust do we have in the privacy of this ConnContext? */
TrustLevel otrng_plugin_context_to_trust(ConnContext *context) {
  TrustLevel level = TRUST_NOT_PRIVATE;

  if (context && context->msgstate == OTRL_MSGSTATE_ENCRYPTED) {
    if (context->active_fingerprint && context->active_fingerprint->trust &&
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
static void process_quitting(void) {
  OtrlUserState userstate = otrng_state->user_state_v3;
  // TODO: use our client_hash to iterate over all active connections
  ConnContext *context = userstate->context_root;
  while (context) {
    ConnContext *next = context->next;
    if (context->msgstate == OTRL_MSGSTATE_ENCRYPTED &&
        context->protocol_version > 1) {

      // TODO: Remove ConnContext
      otrng_plugin_conversation conv[1];
      conv->protocol = context->protocol;
      conv->account = context->accountname;
      conv->peer = context->username;

      otrng_plugin_disconnect(conv);
    }
    context = next;
  }
}

/* Read the maxmsgsizes from a FILE* into the given GHashTable.
 * The FILE* must be open for reading. */
static void mms_read_FILEp(FILE *mmsf, GHashTable *ght) {
  char storeline[50];
  size_t maxsize = sizeof(storeline);

  if (!mmsf) {
    return;
  }

  while (fgets(storeline, maxsize, mmsf)) {
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
    if (!tab) {
      continue;
    }
    *tab = '\0';

    mms = tab + 1;
    tab = strchr(mms, '\t');
    if (tab) {
      continue;
    }
    eol = strchr(mms, '\r');
    if (!eol) {
      eol = strchr(mms, '\n');
    }
    if (!eol) {
      continue;
    }
    *eol = '\0';

    prot_in_table = g_strdup(protocol);
    mms_in_table = malloc(sizeof(int));
    *mms_in_table = atoi(mms);
    g_hash_table_insert(ght, prot_in_table, mms_in_table);
  }
}

static void otrng_str_free(gpointer data) { g_free((char *)data); }

static void otrng_int_free(gpointer data) { g_free((int *)data); }

static void otrng_init_mms_table() {
  /* Hardcoded defaults for maximum message sizes for various
   * protocols.  These can be overridden in the user's MAX_MSG_SIZE+FILE_NAME
   * file. */
  static const struct s_OtrgIdProtPair {
    char *protid;
    int maxmsgsize;
  } mmsPairs[] = {
      {"prpl-msn", 1409},   {"prpl-icq", 2346},    {"prpl-aim", 2343},
      {"prpl-yahoo", 799},  {"prpl-gg", 1999},     {"prpl-irc", 417},
      {"prpl-oscar", 2343}, {"prpl-novell", 1792}, {NULL, 0}};
  int i = 0;
  gchar *maxmsgsizefile;
  FILE *mmsf;

  otrng_max_message_size_table = g_hash_table_new_full(
      g_str_hash, g_str_equal, otrng_str_free, otrng_int_free);

  for (i = 0; mmsPairs[i].protid != NULL; i++) {
    char *nextprot = g_strdup(mmsPairs[i].protid);
    int *nextsize = g_malloc(sizeof(int));
    *nextsize = mmsPairs[i].maxmsgsize;
    g_hash_table_insert(otrng_max_message_size_table, nextprot, nextsize);
  }

  maxmsgsizefile =
      g_build_filename(purple_user_dir(), MAX_MSG_SIZE_FILE_NAME, NULL);

  if (maxmsgsizefile) {
    mmsf = g_fopen(maxmsgsizefile, "rt");
    /* Actually read the file here */
    if (mmsf) {
      mms_read_FILEp(mmsf, otrng_max_message_size_table);
      fclose(mmsf);
    }
    g_free(maxmsgsizefile);
  }
}

static void otrng_free_mms_table() {
  g_hash_table_destroy(otrng_max_message_size_table);
  otrng_max_message_size_table = NULL;
}

// TODO: May not be necessary. Remove.
static otrng_plugin_conversation *
client_conversation_to_plugin_conversation(const otrng_s *conv) {
  const char *accountname = conv->client->client_id.account;
  const char *protocol = conv->client->client_id.protocol;

  // TODO: Instance tag?
  return otrng_plugin_conversation_new(accountname, protocol, conv->peer);
}

static void create_privkey_v3(const otrng_client_id_s opdata) {
  otrng_plugin_create_privkey_v3(client_id_to_purple_account(opdata));
}

static void write_expired_client_profile(struct otrng_client_s *client,
                                         const otrng_client_id_s opdata) {
  otrng_plugin_write_expired_client_profile(
      client_id_to_purple_account(opdata));
}

static void write_expired_prekey_profile(struct otrng_client_s *client,
                                         const otrng_client_id_s opdata) {
  otrng_plugin_write_expired_prekey_profile(
      client_id_to_purple_account(opdata));
}

static void gone_secure_v4(const otrng_s *cconv) {
  otrng_plugin_conversation *conv =
      client_conversation_to_plugin_conversation(cconv);
  if (!conv) {
    return;
  }

  otrng_dialog_conversation_connected(conv);
  otrng_plugin_conversation_free(conv);
}

static void gone_insecure_v4(const otrng_s *cconv) {
  otrng_plugin_conversation *conv =
      client_conversation_to_plugin_conversation(cconv);
  if (!conv) {
    return;
  }

  // TODO: ensure otrng_ui_update_keylist() is called here.
  otrng_dialog_conversation_disconnected(conv);
  otrng_plugin_conversation_free(conv);
}

static void fingerprint_seen_v3(const otrng_fingerprint_v3 fp,
                                const otrng_s *cconv) {
  otrng_plugin_conversation *conv =
      client_conversation_to_plugin_conversation(cconv);
  if (!conv) {
    return;
  }

  otrng_dialog_unknown_fingerprint(otrng_state->user_state_v3, conv->account,
                                   conv->protocol, conv->peer, fp);
  otrng_plugin_conversation_free(conv);
}

static void fingerprint_seen_v4(const otrng_fingerprint fp,
                                const otrng_s *cconv) {
  // TODO: use fp to determine if you have seen this fp before
  // See: otrng_dialog_unknown_fingerprint
  // (otrng_gtk_dialog_unknown_fingerprint)
  char *buf;
  char fp_human[OTRNG_FPRINT_HUMAN_LEN];

  otrng_fingerprint_hash_to_human(fp_human, fp);
  if (otrng_plugin_fingerprint_get(fp_human)) {
    return;
  }

  otrng_plugin_conversation *conv =
      client_conversation_to_plugin_conversation(cconv);
  if (!conv) {
    return;
  }

  // TODO: Change the message if we have have already seen another FP for this
  // contact.

  otrng_plugin_fingerprint *info = otrng_plugin_fingerprint_new(
      fp_human, conv->protocol, conv->account, conv->peer);

  if (!info) {
    otrng_plugin_conversation_free(conv);
    return; // ERROR
  }

  buf =
      g_strdup_printf(_("%s has not been authenticated yet.  You "
                        "should <a href=\"%s%s\">authenticate</a> this buddy."),
                      info->username, AUTHENTICATE_HELPURL, _("?lang=en"));

  PurpleConversation *purple_conv = otrng_plugin_userinfo_to_conv(
      conv->account, conv->protocol, conv->peer, 0);

  purple_conversation_write(purple_conv, NULL, buf, PURPLE_MESSAGE_SYSTEM,
                            time(NULL));

  otrng_plugin_conversation_free(conv);
  g_free(buf);
}

static void smp_ask_for_secret_v4(const otrng_s *cconv) {
  if (!cconv) {
    return;
  }

  otrng_plugin_conversation *conv =
      client_conversation_to_plugin_conversation(cconv);
  otrng_dialog_socialist_millionaires(conv);
  otrng_plugin_conversation_free(conv);
}

static void smp_ask_for_answer_v4(const unsigned char *question, size_t q_len,
                                  const otrng_s *cconv) {
  if (!cconv) {
    return;
  }

  // TODO: otrng_dialog_socialist_millionaires_q expects question to be
  // a string, so it will stop at first 0 anyways. having a unsigned char does
  // not help in any way.

  otrng_plugin_conversation *conv =
      client_conversation_to_plugin_conversation(cconv);
  otrng_dialog_socialist_millionaires_q(conv, (const char *)question);
  otrng_plugin_conversation_free(conv);
}

static void smp_update_v4(const otrng_smp_event event,
                          const uint8_t progress_percent,
                          const otrng_s *cconv) {
  if (!cconv) {
    return;
  }

  otrng_plugin_conversation *conv =
      client_conversation_to_plugin_conversation(cconv);

  switch (event) {
  case OTRNG_SMP_EVENT_CHEATED:
    otrng_plugin_abort_smp(conv);
    otrng_dialog_update_smp(conv, event, 0);
    break;
  case OTRNG_SMP_EVENT_ERROR:
    otrng_plugin_abort_smp(conv);
    otrng_dialog_update_smp(conv, event, 0);
    break;
  case OTRNG_SMP_EVENT_ABORT:
    otrng_dialog_update_smp(conv, event, 0);
    break;
  case OTRNG_SMP_EVENT_IN_PROGRESS:
    otrng_dialog_update_smp(conv, event, ((gdouble)progress_percent) / 100.0);
    break;
  case OTRNG_SMP_EVENT_SUCCESS:
    otrng_dialog_update_smp(conv, event, ((gdouble)progress_percent) / 100.0);
    break;
  case OTRNG_SMP_EVENT_FAILURE:
    otrng_dialog_update_smp(conv, event, ((gdouble)progress_percent) / 100.0);
    break;
  default:
    // should be an error
    break;
  }

  otrng_plugin_conversation_free(conv);
}

static void display_error_message(const otrng_error_event event,
                                  string_p *to_display,
                                  const struct otrng_s *cconv) {
  if (!cconv) { // TODO: prob not needed
    return;
  }

  const char *unreadable_msg_error = "Unreadable message";
  const char *not_in_private_error = "Not in private state message";
  const char *encryption_error = "Encryption error";
  const char *malformed_error = "Malformed message";

  switch (event) {
  case OTRNG_ERROR_UNREADABLE_EVENT:
    *to_display =
        otrng_xstrndup(unreadable_msg_error, strlen(unreadable_msg_error));
    break;
  case OTRNG_ERROR_NOT_IN_PRIVATE_EVENT:
    *to_display =
        otrng_xstrndup(not_in_private_error, strlen(not_in_private_error));
    break;
  case OTRNG_ERROR_ENCRYPTION_ERROR_EVENT:
    *to_display = otrng_xstrndup(encryption_error, strlen(encryption_error));
    break;
  case OTRNG_ERROR_MALFORMED_EVENT:
    *to_display = otrng_xstrndup(malformed_error, strlen(malformed_error));
    break;
  case OTRNG_ERROR_NONE:
    break;
  default:
    // should be an error
    break;
  }
}

static otrng_shared_session_state_s
get_shared_session_state_cb(const otrng_s *conv) {
  // TODO: Get those values from the conversation
  return (otrng_shared_session_state_s){
      .identifier1 = g_strdup("alice"),
      .identifier2 = g_strdup("bob"),
      .password = NULL,
  };
}

static otrng_result
get_account_and_protocol_cb(char **account_name, char **protocol_name,
                            const otrng_client_id_s client_id) {
  *account_name = g_strdup(client_id.account);
  *protocol_name = g_strdup(client_id.protocol);

  return OTRNG_SUCCESS;
}

static otrng_client_callbacks_s *otrng_plugin_client_callbacks_new(void) {
  otrng_client_callbacks_s *cb =
      otrng_xmalloc_z(sizeof(otrng_client_callbacks_s));

  cb->get_account_and_protocol = get_account_and_protocol_cb;
  cb->create_instag = create_instag_cb;
  // TODO move to long_term_keys.c
  cb->create_privkey_v3 = create_privkey_v3;
  cb->write_expired_client_profile = write_expired_client_profile;
  cb->write_expired_prekey_profile = write_expired_prekey_profile;
  cb->gone_secure = gone_secure_v4;
  cb->gone_insecure = gone_insecure_v4;
  cb->fingerprint_seen = fingerprint_seen_v4;
  cb->fingerprint_seen_v3 = fingerprint_seen_v3;
  cb->smp_ask_for_secret = smp_ask_for_secret_v4;
  cb->smp_ask_for_answer = smp_ask_for_answer_v4;
  cb->smp_update = smp_update_v4;
  cb->display_error_message = display_error_message;
  cb->get_shared_session_state = get_shared_session_state_cb;

  return cb;
}

static int otrng_plugin_init_userstate(void) {
  gchar *privkeyfile3 = NULL;
  gchar *storefile = NULL;
  gchar *instagfile = NULL;
  gchar *exp_client_profile_filename = NULL;
  gchar *exp_prekey_profile_filename = NULL;

  privkeyfile3 = g_build_filename(purple_user_dir(), PRIVKEY_FILE_NAME, NULL);
  storefile = g_build_filename(purple_user_dir(), STORE_FILE_NAME_v4, NULL);
  instagfile = g_build_filename(purple_user_dir(), INSTAG_FILE_NAME, NULL);
  exp_client_profile_filename =
      g_build_filename(purple_user_dir(), EXP_CLIENT_PROFILE_FILE_NAME, NULL);
  exp_prekey_profile_filename =
      g_build_filename(purple_user_dir(), EXP_PREKEY_PROFILE_FILE_NAME, NULL);

  if (!privkeyfile3 || !storefile || !instagfile ||
      !exp_client_profile_filename || !exp_prekey_profile_filename) {
    g_free(privkeyfile3);
    g_free(storefile);
    g_free(instagfile);
    g_free(exp_client_profile_filename);
    g_free(exp_prekey_profile_filename);

    return 1;
  }

  FILE *priv3f = g_fopen(privkeyfile3, "rb");
  FILE *storef = g_fopen(storefile, "rb");
  FILE *instagf = g_fopen(instagfile, "rb");
  FILE *exp_client_profile_f = g_fopen(exp_client_profile_filename, "rb");
  FILE *exp_prekey_profile_filep = g_fopen(exp_prekey_profile_filename, "rb");

  g_free(privkeyfile3);
  g_free(storefile);
  g_free(instagfile);
  g_free(exp_client_profile_filename);
  g_free(exp_prekey_profile_filename);

  otrng_client_callbacks_s *callbacks = otrng_plugin_client_callbacks_new();
  long_term_keys_set_callbacks(callbacks);
  profiles_set_callbacks(callbacks);
  prekeys_set_callbacks(callbacks);

  otrng_state = otrng_global_state_new(callbacks, otrng_true);

  /* Read instance tags to both V4 and V3 libraries' storage */
  otrng_plugin_read_instance_tags_FILEp(instagf);

  // Read V3 private key from files
  otrng_plugin_read_private_keys(priv3f, NULL);

  /* Read fingerprints to OTR4 fingerprint store */
  otrng_plugin_fingerprint_store_create();
  otrng_plugin_read_fingerprints_FILEp(storef);
  otrng_ui_update_fingerprint(); /* Updates the view */

  /* Read exp client profile */
  otrng_plugin_read_expired_client_profile(exp_client_profile_f);

  /* Read prekey profile */
  otrng_plugin_read_expired_prekey_profile(exp_prekey_profile_filep);

  if (priv3f) {
    fclose(priv3f);
  }

  if (storef) {
    fclose(storef);
  }

  if (instagf) {
    fclose(instagf);
  }

  return 0;
}

static void otrng_plugin_cleanup_userstate(void) {
  g_hash_table_remove_all(otrng_fingerprints_table);
  otrng_ui_update_fingerprint(); // Updates the view
  otrng_fingerprints_table = NULL;

  otrng_global_state_free(otrng_state);
  otrng_state = NULL;
}

#if BETA_DIALOG && defined USING_GTK /* Only for beta */
static int build_beta_dialog(void) {
  GtkWidget *dialog;
  GtkWidget *dialog_text;
  PidginBuddyList *blist;
  gchar *buf = NULL;

  blist = pidgin_blist_get_default_gtk_blist();

  if (time(NULL) > 1356998400) /* 2013-01-01 */ {
    buf = g_strdup_printf(_("OTR PLUGIN v%s"), PIDGIN_OTR_VERSION);
    dialog = gtk_dialog_new_with_buttons(
        buf, GTK_WINDOW(blist->window),
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT, GTK_STOCK_OK,
        GTK_RESPONSE_ACCEPT, NULL);
    dialog_text = gtk_label_new(NULL);
    gtk_widget_set_size_request(dialog_text, 350, 100);
    gtk_label_set_line_wrap(GTK_LABEL(dialog_text), TRUE);
    g_free(buf);
    buf = g_strdup_printf(
        _("This beta copy of the "
          "Off-the-Record Messaging v%s Pidgin plugin has expired as of "
          "2013-01-01. Please look for an updated release at "
          "http://otr.cypherpunks.ca/"),
        PIDGIN_OTR_VERSION);
    gtk_label_set_text(GTK_LABEL(dialog_text), buf);
    gtk_widget_show(dialog_text);
    gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), dialog_text, TRUE,
                       TRUE, 0);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);

    g_free(buf);
    return 1;
  }

  buf = g_strdup_printf(_("OTR PLUGIN v%s"), PIDGIN_OTR_VERSION);
  dialog = gtk_dialog_new_with_buttons(buf, GTK_WINDOW(blist->window),
                                       GTK_DIALOG_MODAL |
                                           GTK_DIALOG_DESTROY_WITH_PARENT,
                                       GTK_STOCK_OK, GTK_RESPONSE_ACCEPT, NULL);
  dialog_text = gtk_label_new(NULL);
  gtk_widget_set_size_request(dialog_text, 350, 100);
  gtk_label_set_line_wrap(GTK_LABEL(dialog_text), TRUE);
  g_free(buf);
  buf = g_strdup_printf(
      _("You have enabled a beta "
        "version of the Off-the-Record Messaging v%s Pidgin plugin. "
        "This version is intended for testing purposes only and is not "
        "for general purpose use."),
      PIDGIN_OTR_VERSION);
  gtk_label_set_text(GTK_LABEL(dialog_text), buf);
  gtk_widget_show(dialog_text);
  gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), dialog_text, TRUE, TRUE,
                     0);
  gtk_dialog_run(GTK_DIALOG(dialog));
  gtk_widget_destroy(dialog);
  g_free(buf);

  return 0;
}
#endif

static void otrng_plugin_watch_libpurple_events(void) {
  void *conv_handle = purple_conversations_get_handle();
  void *conn_handle = purple_connections_get_handle();
  void *blist_handle = purple_blist_get_handle();
  void *core_handle = purple_get_core();

  purple_signal_connect(core_handle, "quitting", otrng_plugin_handle,
                        PURPLE_CALLBACK(process_quitting), NULL);
  purple_signal_connect(conv_handle, "sending-im-msg", otrng_plugin_handle,
                        PURPLE_CALLBACK(process_sending_im), NULL);
  purple_signal_connect(conv_handle, "receiving-im-msg", otrng_plugin_handle,
                        PURPLE_CALLBACK(process_receiving_im), NULL);
  purple_signal_connect(conv_handle, "conversation-updated",
                        otrng_plugin_handle,
                        PURPLE_CALLBACK(process_conv_updated), NULL);
  purple_signal_connect(conv_handle, "conversation-created",
                        otrng_plugin_handle,
                        PURPLE_CALLBACK(process_conv_create_cb), NULL);
  purple_signal_connect(conv_handle, "deleting-conversation",
                        otrng_plugin_handle,
                        PURPLE_CALLBACK(process_conv_destroyed), NULL);
  purple_signal_connect(conn_handle, "signed-on", otrng_plugin_handle,
                        PURPLE_CALLBACK(process_connection_change), NULL);
  purple_signal_connect(conn_handle, "signed-off", otrng_plugin_handle,
                        PURPLE_CALLBACK(process_connection_change), NULL);
  purple_signal_connect(blist_handle, "blist-node-extended-menu",
                        otrng_plugin_handle,
                        PURPLE_CALLBACK(supply_extended_menu), NULL);
}

static void otrng_plugin_unwatch_libpurple_events(void) {
  void *conv_handle = purple_conversations_get_handle();
  void *conn_handle = purple_connections_get_handle();
  void *blist_handle = purple_blist_get_handle();
  void *core_handle = purple_get_core();

  purple_signal_disconnect(core_handle, "quitting", otrng_plugin_handle,
                           PURPLE_CALLBACK(process_quitting));
  purple_signal_disconnect(conv_handle, "sending-im-msg", otrng_plugin_handle,
                           PURPLE_CALLBACK(process_sending_im));
  purple_signal_disconnect(conv_handle, "receiving-im-msg", otrng_plugin_handle,
                           PURPLE_CALLBACK(process_receiving_im));
  purple_signal_disconnect(conv_handle, "conversation-updated",
                           otrng_plugin_handle,
                           PURPLE_CALLBACK(process_conv_updated));
  purple_signal_disconnect(conv_handle, "conversation-created",
                           otrng_plugin_handle,
                           PURPLE_CALLBACK(process_conv_create_cb));
  purple_signal_disconnect(conv_handle, "deleting-conversation",
                           otrng_plugin_handle,
                           PURPLE_CALLBACK(process_conv_destroyed));
  purple_signal_disconnect(conn_handle, "signed-on", otrng_plugin_handle,
                           PURPLE_CALLBACK(process_connection_change));
  purple_signal_disconnect(conn_handle, "signed-off", otrng_plugin_handle,
                           PURPLE_CALLBACK(process_connection_change));
  purple_signal_disconnect(blist_handle, "blist-node-extended-menu",
                           otrng_plugin_handle,
                           PURPLE_CALLBACK(supply_extended_menu));
}

/* Return 1 if the given protocol supports OTR, 0 otherwise. */
int otrng_plugin_proto_supports_otr(const char *proto) {
  /* Right now, OTR should work on all protocols, possibly
   * with the help of fragmentation. */
  return 1;
}

int otrng_plugin_conversation_to_protocol_version(
    const otrng_plugin_conversation *conv) {
  return 4; // TODO: get this from the OTR conversation
}

#if defined USING_GTK
static void warn_otrv3_installed(void) {
  GtkWidget *dialog;
  GtkWidget *dialog_text;
  PidginBuddyList *blist;
  gchar *buf = NULL;

  blist = pidgin_blist_get_default_gtk_blist();

  buf = g_strdup_printf(_("OTRNG PLUGIN v%s"), PIDGIN_OTR_VERSION);
  dialog = gtk_dialog_new_with_buttons(buf, GTK_WINDOW(blist->window),
                                       GTK_DIALOG_MODAL |
                                           GTK_DIALOG_DESTROY_WITH_PARENT,
                                       GTK_STOCK_OK, GTK_RESPONSE_ACCEPT, NULL);
  dialog_text = gtk_label_new(NULL);
  gtk_widget_set_size_request(dialog_text, 550, 300);
  gtk_label_set_line_wrap(GTK_LABEL(dialog_text), TRUE);
  g_free(buf);
  buf = g_strdup_printf(
      _("You have enabled two conflicing plugins providing "
        "different versions of the Off-the-Record Messaging plugin. "
        "It is recommended that you go to Tools->Plugins and disable "
        "the plugin named \"Off-the-Record Messaging\", while leaving "
        "the plugin named \"Off-the-Record Messaging nextgen\" enabled, "
        "and then restart. "
        "Not doing so could produce unwanted effects, including crashes."));
  gtk_label_set_text(GTK_LABEL(dialog_text), buf);
  gtk_widget_show(dialog_text);
  gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), dialog_text, TRUE, TRUE,
                     0);
  gtk_dialog_run(GTK_DIALOG(dialog));
  gtk_widget_destroy(dialog);
  g_free(buf);
}
#endif

gboolean otrng_plugin_load(PurplePlugin *handle) {
  PurplePlugin *plug = purple_plugins_find_with_id("otr");
  if (plug != NULL && purple_plugin_is_loaded(plug)) {
#if defined USING_GTK
    warn_otrv3_installed();
#endif
    return FALSE;
  }

  if (otrng_plugin_init_userstate()) {
    return FALSE;
  }

#if BETA_DIALOG && defined USING_GTK /* Only for beta */
  if (build_beta_dialog())
    return FALSE;
#endif

  otrng_init_mms_table();
  otrng_plugin_handle = handle;
  otrng_plugin_timerid = 0;

  otrng_ui_init();
  otrng_dialog_init();

  purple_conversation_foreach(process_conv_create);

  otrng_plugin_watch_libpurple_events();

  // Loads prekey plugin
  otrng_prekey_plugin_load(handle);
  otrng_plugin_prekey_discovery_load();

  return TRUE;
}

gboolean otrng_plugin_unload(PurplePlugin *handle) {
  otrng_plugin_prekey_discovery_unload();

  // Unload prekey plugin
  otrng_prekey_plugin_unload(handle);

  otrng_plugin_unwatch_libpurple_events();

  /* Clean up all of our state. */
  purple_conversation_foreach(otrng_dialog_remove_conv);

  otrng_dialog_cleanup();
  otrng_ui_cleanup();

  /* Stop the timer, if necessary */
  stop_start_timer(0);

  otrng_plugin_handle = NULL;
  otrng_free_mms_table();

  otrng_plugin_cleanup_userstate();

  return TRUE;
}
