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

#include "ui.h"

/* system headers */
#include <stdlib.h>

/* purple headers */
#include <account.h>
#include <util.h>

#ifdef ENABLE_NLS
/* internationalisation header */
#include <glib/gi18n-lib.h>
#else
#define _(x) (x)
#define N_(x) (x)
#endif

#include <libotr/proto.h>
/* libotr headers */
#include <libotr/message.h>
#include <libotr/privkey.h>

/* pidgin-otrng headers */
#include "dialogs.h"
#include "pidgin-helpers.h"
#include "plugin-all.h"

static const OtrgUiUiOps *ui_ops = NULL;

/* Set the UI ops */
void otrng_ui_set_ui_ops(const OtrgUiUiOps *ops) { ui_ops = ops; }

/* Get the UI ops */
const OtrgUiUiOps *otrng_ui_get_ui_ops(void) { return ui_ops; }

/* Initialize the OTR UI subsystem */
void otrng_ui_init(void) {
  if (ui_ops != NULL) {
    ui_ops->init();
  }
}

/* Deinitialize the OTR UI subsystem */
void otrng_ui_cleanup(void) {
  if (ui_ops != NULL) {
    ui_ops->cleanup();
  }
}

/* Call this function when the DSA key is updated; it will redraw the
 * UI, if visible. */
void otrng_ui_update_fingerprint(void) {
  if (ui_ops != NULL) {
    ui_ops->update_fingerprint();
  }
}

/* Update the keylist, if it's visible */
void otrng_ui_update_keylist(void) {
  if (ui_ops != NULL) {
    ui_ops->update_keylist();
  }
}

/* Drop a context to PLAINTEXT state */
void otrng_ui_disconnect_connection(otrng_plugin_conversation *conv) {
  otrng_client_s *client = get_otrng_client(conv->protocol, conv->account);
  if (!client) {
    return;
  }

  otrng_conversation_s *otr_conv =
      otrng_client_get_conversation(0, conv->peer, client);

  /* Don't do anything with fingerprints other than the active one
   * if we're in the ENCRYPTED state */
  if (otrng_conversation_is_encrypted(otr_conv)) {
    otrng_plugin_disconnect(conv);
  }
}

// TODO: should not this be in another file?
/* Forget a fingerprint */
void otrng_ui_forget_fingerprint(otrng_plugin_fingerprint *fingerprint) {
  if (fingerprint == NULL) {
    return;
  }

  otrng_conversation_s *otr_conv =
      otrng_plugin_fingerprint_to_otr_conversation(fingerprint);

  /* Don't do anything with the active fingerprint if we're in the
   * ENCRYPTED state. */
  if (otrng_conversation_is_encrypted(otr_conv)) {
    return;
  }

  otrng_plugin_fingerprint_forget(fingerprint->fp);
  otrng_plugin_write_fingerprints();

  otrng_ui_update_keylist();
}

/* Configure OTR for a particular buddy */
void otrng_ui_config_buddy(PurpleBuddy *buddy) {
  if (ui_ops != NULL) {
    ui_ops->config_buddy(buddy);
  }
}

/* Load the preferences for a particular account / username */
void otrng_ui_get_prefs(OtrgUiPrefs *prefsp, PurpleAccount *account,
                        const char *name) {
  /* Check to see if the protocol for this account supports OTR at all. */
  const char *proto = purple_account_get_protocol_id(account);
  if (!otrng_plugin_proto_supports_otr(proto)) {
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

// TODO: change the name later and remove the above func
/* Load the preferences for a particular account / username */
void otrng_v4_ui_get_prefs(otrng_ui_prefs *prefs, PurpleAccount *account) {
  /* Check to see if the protocol for this account supports OTR at all. */
  const char *proto = purple_account_get_protocol_id(account);
  if (!otrng_plugin_proto_supports_otr(proto)) {
    prefs->policy.allows = OTRNG_ALLOW_NONE;
    prefs->avoid_logging_otr = TRUE;
    prefs->show_otr_button = FALSE;
    return;
  }

  // TODO: for the moment
  // if (ui_ops != NULL) {
  //  ui_ops->get_prefs_v4(prefs, account);
  //  return;
  //}
  /* If we've got no other way to get the prefs, use sensible defaults */
  prefs->policy.allows = OTRNG_POLICY_DEFAULT;
  prefs->avoid_logging_otr = TRUE;
  prefs->show_otr_button = FALSE;
}
